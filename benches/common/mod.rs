//! Bench-side helpers shared between [`handshake`] and [`throughput`].
//!
//! Three TLS stacks are spun up against the same `tests/data/cert.pem`
//! fixture so the only moving variable is the engine driving the
//! record layer:
//!
//! - [`AwsLcStack`] — this crate. Two flavours: `userspace` (both
//!   sides call `disable_ktls()` so reads/writes stay in `SSL_read` /
//!   `SSL_write`) and `ktls` (default, so the engine auto-installs
//!   kernel TLS once the handshake finishes; Linux-only).
//! - [`RustlsStack`] — `tokio-rustls` with the `aws-lc-rs` crypto
//!   provider. Same `libcrypto` primitives as us (both ultimately
//!   route through `aws-lc-sys`); the comparison isolates "rustls
//!   record-layer + state machine" overhead from "raw `libssl`
//!   + `AsyncFd`" overhead.
//!
//! Each stack exposes an `Arc<Acceptor>` and an `Arc<Connector>` that
//! the bench drives. The accept side runs in a permanent background
//! task that reads-and-discards anything the client sends so the
//! transport is back-pressured by real network buffering and not by
//! the bench harness.

use std::sync::{Arc, Once};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;
use tokio_rustls::rustls;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::crypto::CryptoProvider;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use tokio_rustls::rustls::{DigitallySignedStruct, SignatureScheme};

pub const CERT_PEM: &[u8] = include_bytes!("../../tests/data/cert.pem");
pub const KEY_PEM: &[u8] = include_bytes!("../../tests/data/key.pem");

/// Build a multi-thread Tokio runtime so the server accept loop, the
/// per-connection task, and the client iter can actually run in
/// parallel on loopback rather than serializing on a single worker.
pub fn build_runtime() -> Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("tokio runtime")
}

fn install_rustls_provider() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .ok();
    });
}

// ---------- tokio-aws-lc ----------

pub struct AwsLcStack {
    pub acceptor: tokio_aws_lc::TlsAcceptor,
    pub connector: tokio_aws_lc::TlsConnector,
}

impl AwsLcStack {
    /// `userspace = true` calls `disable_ktls()` on both sides so the
    /// data path stays in `SSL_read` / `SSL_write` after the
    /// handshake. With `false`, the engine auto-installs kTLS
    /// immediately after the handshake completes (Linux only — on
    /// other targets the auto-install is a no-op and the data path
    /// remains userspace regardless).
    pub fn new(userspace: bool) -> Self {
        // AWS-LC's default key-exchange group list leads with the
        // hybrid post-quantum `X25519MLKEM768`, which is ~65µs slower
        // per handshake than classical X25519. `tokio-rustls` with
        // the `aws-lc-rs` provider at 0.23 / 0.26 offers the classical
        // groups only by default. We pin both stacks to the same
        // classical-only list so the bench compares engine-level
        // overhead instead of "we picked PQ, they didn't".
        let groups = [
            tokio_aws_lc::NamedGroup::X25519,
            tokio_aws_lc::NamedGroup::Secp256r1,
            tokio_aws_lc::NamedGroup::Secp384r1,
            tokio_aws_lc::NamedGroup::Secp521r1,
        ];
        let mut server_builder = tokio_aws_lc::ServerConfig::builder().named_groups(&groups);
        let mut client_builder = tokio_aws_lc::ClientConfig::builder().named_groups(&groups);
        if userspace {
            server_builder = server_builder.disable_ktls();
            client_builder = client_builder.disable_ktls();
        }
        let server_cfg = Arc::new(
            server_builder
                .with_pem_bytes(CERT_PEM, KEY_PEM)
                .expect("tokio-aws-lc ServerConfig builds"),
        );
        // The test fixture is self-signed without CA basic-constraints,
        // so neither rustls' webpki nor a strict path walk will accept
        // it as a trust anchor for itself. We turn off path validation
        // on both stacks so the comparison is apples-to-apples; the
        // TLS CertificateVerify signature check is still performed by
        // both engines, which is the relevant work for a bench.
        let client_cfg = Arc::new(
            client_builder
                .dangerous_disable_verification()
                .build()
                .expect("tokio-aws-lc ClientConfig builds"),
        );
        Self {
            acceptor: tokio_aws_lc::TlsAcceptor::new(server_cfg),
            connector: tokio_aws_lc::TlsConnector::new(client_cfg),
        }
    }
}

// ---------- rustls (via tokio-rustls) ----------

pub struct RustlsStack {
    pub acceptor: tokio_rustls::TlsAcceptor,
    pub connector: tokio_rustls::TlsConnector,
}

impl RustlsStack {
    pub fn new() -> Self {
        install_rustls_provider();

        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(CERT_PEM)
            .collect::<Result<_, _>>()
            .expect("parse server certs");
        let key = PrivateKeyDer::from_pem_slice(KEY_PEM).expect("parse server key");

        let server_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("rustls server cfg");

        let provider = CryptoProvider::get_default()
            .cloned()
            .expect("default crypto provider installed");
        let verifier = Arc::new(AcceptAnyServerCert { provider });
        let client_cfg = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();

        Self {
            acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg)),
            connector: tokio_rustls::TlsConnector::from(Arc::new(client_cfg)),
        }
    }
}

/// Skip path validation but keep the TLS-level signature check. This
/// matches what our [`tokio_aws_lc::ClientConfigBuilder::dangerous_disable_verification`]
/// switch does on the AWS-LC side (which sets `SSL_VERIFY_NONE` — the
/// per-handshake `CertificateVerify` check still runs).
#[derive(Debug)]
struct AcceptAnyServerCert {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ---------- accept-and-drain server tasks ----------

/// Result of starting a background acceptor: the port the client
/// should connect to. The listener is leaked into the runtime; benches
/// run for a few seconds and the runtime is dropped at the end of the
/// bench function.
pub struct BoundServer {
    pub port: u16,
}

/// Spawn a `tokio-aws-lc` accept loop that, for each inbound
/// connection, performs the handshake and (when `drain` is set)
/// reads-and-discards bytes until EOF.
pub async fn spawn_awslc_server(acceptor: tokio_aws_lc::TlsAcceptor, drain: bool) -> BoundServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("local_addr").port();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let _ = tcp.set_nodelay(true);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(tcp).await else {
                    return;
                };
                if drain {
                    let mut buf = vec![0u8; 64 * 1024];
                    loop {
                        match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {}
                        }
                    }
                }
                let _ = stream.shutdown().await;
            });
        }
    });
    BoundServer { port }
}

/// Spawn a `tokio-rustls` accept loop with the same shape as
/// [`spawn_awslc_server`].
pub async fn spawn_rustls_server(acceptor: tokio_rustls::TlsAcceptor, drain: bool) -> BoundServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("local_addr").port();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let _ = tcp.set_nodelay(true);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(tcp).await else {
                    return;
                };
                if drain {
                    let mut buf = vec![0u8; 64 * 1024];
                    loop {
                        match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {}
                        }
                    }
                }
                let _ = stream.shutdown().await;
            });
        }
    });
    BoundServer { port }
}

/// Open a TCP socket with `TCP_NODELAY` set so per-record latency does
/// not get bundled into Nagle's algorithm during throughput tests.
pub async fn tcp_connect(port: u16) -> TcpStream {
    let tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("tcp connect");
    let _ = tcp.set_nodelay(true);
    tcp
}
