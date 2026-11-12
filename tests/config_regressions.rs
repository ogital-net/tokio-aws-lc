//! Configuration regressions use loopback TCP and explicitly disable kTLS.

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio_aws_lc::cipher_suite::{
    TLS13_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
};
use tokio_aws_lc::{
    CipherSuite, ClientAuthMode, ClientConfig, ClientConfigBuilder, Error, ProtocolVersion, Result,
    ServerConfig, ServerConfigBuilder, TlsAcceptor, TlsConnector, TlsStream,
};

const CERT_DER: &[u8] = include_bytes!("data/cert.der");
const KEY_DER: &[u8] = include_bytes!("data/key.der");
const CERT_PEM: &[u8] = include_bytes!("data/cert.pem");
const KEY_PEM: &[u8] = include_bytes!("data/key.pem");
const KEY_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/key.pem");
const CA_EXTENSIONS: &str =
    "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n";
const MIXED: &[&CipherSuite] = &[
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS13_AES_128_GCM_SHA256,
];
const CASES: [(ProtocolVersion, &CipherSuite, &str, &str); 2] = [
    (
        ProtocolVersion::Tls12,
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        "TLSv1.2",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
    ),
    (
        ProtocolVersion::Tls13,
        TLS13_AES_128_GCM_SHA256,
        "TLSv1.3",
        "TLS_AES_128_GCM_SHA256",
    ),
];
const OMITTED: [(&CipherSuite, ProtocolVersion); 2] = [
    (
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        ProtocolVersion::Tls13,
    ),
    (TLS13_AES_128_GCM_SHA256, ProtocolVersion::Tls12),
];

fn client_builder() -> ClientConfigBuilder {
    ClientConfig::builder()
        .with_root_certs_der_bytes(&[CERT_DER])
        .disable_ktls()
}

fn server_builder() -> ServerConfigBuilder {
    ServerConfig::builder().disable_ktls()
}

fn openssl(command: &mut Command) -> Vec<u8> {
    let output = command.output().expect("run openssl");
    assert!(
        output.status.success(),
        "{command:?} failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

struct TestCertificates(PathBuf);

impl TestCertificates {
    fn new() -> Self {
        static NEXT_DIR: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "tokio-aws-lc-config-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        Self(dir)
    }

    fn issue(&self, name: &str, issuer: Option<&str>, extensions: &str) -> Vec<u8> {
        static NEXT_SERIAL: AtomicU64 = AtomicU64::new(1);
        let csr = self.0.join(format!("{name}.csr"));
        let cert = self.0.join(format!("{name}.pem"));
        let extfile = self.0.join(format!("{name}.ext"));
        std::fs::write(&extfile, extensions).unwrap();
        openssl(
            Command::new("openssl")
                .args(["req", "-new", "-sha256", "-key", KEY_PATH])
                .args(["-subj", &format!("/CN={name}")])
                .arg("-out")
                .arg(&csr),
        );
        let mut command = Command::new("openssl");
        command
            .args(["x509", "-req", "-sha256", "-days", "1", "-in"])
            .arg(csr)
            .arg("-extfile")
            .arg(extfile)
            .arg("-set_serial")
            .arg(NEXT_SERIAL.fetch_add(1, Ordering::Relaxed).to_string())
            .arg("-out")
            .arg(&cert);
        if let Some(issuer) = issuer {
            command
                .arg("-CA")
                .arg(self.0.join(format!("{issuer}.pem")))
                .args(["-CAkey", KEY_PATH]);
        } else {
            command.args(["-signkey", KEY_PATH]);
        }
        openssl(&mut command);
        std::fs::read(cert).unwrap()
    }
}

impl Drop for TestCertificates {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn handshake(
    client: ClientConfig,
    server: ServerConfig,
) -> (Result<TlsStream>, Result<TlsStream>) {
    handshake_named(client, server, "localhost").await
}

async fn handshake_named(
    client: ClientConfig,
    server: ServerConfig,
    server_name: &str,
) -> (Result<TlsStream>, Result<TlsStream>) {
    tokio::time::timeout(Duration::from_secs(5), async move {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connector = TlsConnector::new(Arc::new(client));
        let acceptor = TlsAcceptor::new(Arc::new(server));
        // Keep successful streams alive until both handshakes finish, and
        // drop both futures on timeout rather than leaving detached tasks.
        tokio::join!(
            async {
                let tcp = TcpStream::connect(addr).await.unwrap();
                connector.connect(server_name, tcp).await
            },
            async {
                let (tcp, _) = listener.accept().await.unwrap();
                acceptor.accept(tcp).await
            }
        )
    })
    .await
    .expect("configuration handshake must finish, not hang")
}

fn server_certificate(common_name: &str, san: Option<&str>) -> Vec<u8> {
    let mut command = Command::new("openssl");
    command
        .args(["req", "-new", "-x509", "-sha256", "-days", "1", "-key"])
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/key.pem"))
        .args(["-subj", &format!("/CN={common_name}")])
        .args(["-addext", "basicConstraints=critical,CA:FALSE"])
        .args(["-addext", "extendedKeyUsage=serverAuth"]);
    if let Some(san) = san {
        command.args(["-addext", &format!("subjectAltName={san}")]);
    }
    let output = command.output().expect("openssl req");
    assert!(output.status.success(), "openssl req failed: {output:?}");
    output.stdout
}

#[tokio::test]
async fn common_name_fallback_is_explicit_and_can_be_disabled_again() {
    let cert = server_certificate("localhost", None);
    for version in [ProtocolVersion::Tls12, ProtocolVersion::Tls13] {
        for fallback in [None, Some(true), Some(false)] {
            let mut builder = ClientConfig::builder()
                .with_root_certs_pem_bytes(&cert)
                .disable_ktls();
            if let Some(allow) = fallback {
                builder = builder
                    .allow_common_name_fallback(true)
                    .allow_common_name_fallback(allow);
            }
            let client = builder.build().unwrap();
            let server = server_builder()
                .min_protocol_version(version)
                .max_protocol_version(version)
                .with_pem_bytes(&cert, include_bytes!("data/key.pem"))
                .unwrap();
            let (client, server) = handshake(client, server).await;
            assert_eq!(
                client.is_ok(),
                fallback == Some(true),
                "{version:?}, {fallback:?}: {client:?}"
            );
            assert_eq!(
                server.is_ok(),
                fallback == Some(true),
                "{version:?}, {fallback:?}: {server:?}"
            );
        }
    }
}

#[tokio::test]
async fn dns_sans_take_precedence_over_common_name() {
    for (common_name, san, accepted) in [
        ("localhost", "DNS:other.invalid", false),
        ("other.invalid", "DNS:localhost", true),
    ] {
        let cert = server_certificate(common_name, Some(san));
        for version in [ProtocolVersion::Tls12, ProtocolVersion::Tls13] {
            for fallback in [false, true] {
                let client = ClientConfig::builder()
                    .with_root_certs_pem_bytes(&cert)
                    .allow_common_name_fallback(fallback)
                    .disable_ktls()
                    .build()
                    .unwrap();
                let server = server_builder()
                    .min_protocol_version(version)
                    .max_protocol_version(version)
                    .with_pem_bytes(&cert, include_bytes!("data/key.pem"))
                    .unwrap();
                let (client, server) = handshake(client, server).await;
                assert_eq!(
                    client.is_ok(),
                    accepted,
                    "{version:?}, {fallback}: {client:?}"
                );
                assert_eq!(
                    server.is_ok(),
                    accepted,
                    "{version:?}, {fallback}: {server:?}"
                );
            }
        }
    }
}

#[tokio::test]
async fn common_name_fallback_never_authenticates_ip_addresses() {
    let cert = server_certificate("127.0.0.1", None);
    for fallback in [false, true] {
        let client = ClientConfig::builder()
            .with_root_certs_pem_bytes(&cert)
            .allow_common_name_fallback(fallback)
            .disable_ktls()
            .build()
            .unwrap();
        let server = server_builder()
            .with_pem_bytes(&cert, include_bytes!("data/key.pem"))
            .unwrap();
        let (client, server) = handshake_named(client, server, "127.0.0.1").await;
        assert!(client.is_err());
        assert!(server.is_err());
    }
}

#[tokio::test]
async fn mtls_accepts_five_intermediates_and_rejects_six() {
    let certificates = TestCertificates::new();
    let root = certificates.issue("root", None, CA_EXTENSIONS);
    let mut intermediates = Vec::new();
    for depth in 1..=6 {
        let issuer = if depth == 1 {
            "root".to_owned()
        } else {
            format!("intermediate-{}", depth - 1)
        };
        intermediates.push(certificates.issue(
            &format!("intermediate-{depth}"),
            Some(&issuer),
            CA_EXTENSIONS,
        ));
    }
    for depth in [5, 6] {
        let leaf_name = format!("client-{depth}");
        let mut chain = certificates.issue(
            &leaf_name,
            Some(&format!("intermediate-{depth}")),
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n",
        );
        let mut untrusted = Vec::new();
        for intermediate in intermediates[..depth].iter().rev() {
            untrusted.extend_from_slice(intermediate);
        }
        let untrusted_path = certificates.0.join("intermediates.pem");
        std::fs::write(&untrusted_path, &untrusted).unwrap();
        openssl(
            Command::new("openssl")
                .args([
                    "verify",
                    "-purpose",
                    "sslclient",
                    "-verify_depth",
                    "6",
                    "-CAfile",
                ])
                .arg(certificates.0.join("root.pem"))
                .arg("-untrusted")
                .arg(untrusted_path)
                .arg(certificates.0.join(format!("{leaf_name}.pem"))),
        );
        chain.extend_from_slice(&untrusted);
        chain.extend_from_slice(&root);
        for version in [ProtocolVersion::Tls12, ProtocolVersion::Tls13] {
            for mode in [ClientAuthMode::Optional, ClientAuthMode::Required] {
                let client = client_builder()
                    .with_client_auth_pem_bytes(&chain, KEY_PEM)
                    .build()
                    .unwrap();
                let server = server_builder()
                    .client_auth(mode, &root)
                    .min_protocol_version(version)
                    .max_protocol_version(version)
                    .with_der_bytes(&[CERT_DER], KEY_DER)
                    .unwrap();
                let (client, server) = handshake(client, server).await;
                if depth == 5 {
                    assert!(client.is_ok(), "{version:?}, {mode:?}: {client:?}");
                    assert!(server.is_ok(), "{version:?}, {mode:?}: {server:?}");
                } else {
                    assert!(
                        matches!(server, Err(Error::Handshake(_))),
                        "{version:?}, {mode:?}: {server:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn mtls_trust_roots_exclude_default_verify_paths() {
    const CHILD_ROOTS_DIR: &str = "TOKIO_AWS_LC_TEST_DEFAULT_ROOTS_DIR";
    let Some(dir) = std::env::var_os(CHILD_ROOTS_DIR) else {
        let certificates = TestCertificates::new();
        certificates.issue("root", None, CA_EXTENSIONS);
        certificates.issue(
            "peer",
            Some("root"),
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:localhost\n",
        );
        let empty_dir = certificates.0.join("empty");
        std::fs::create_dir(&empty_dir).unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "mtls_trust_roots_exclude_default_verify_paths",
                "--nocapture",
            ])
            .env(CHILD_ROOTS_DIR, &certificates.0)
            .env("SSL_CERT_FILE", certificates.0.join("root.pem"))
            .env("SSL_CERT_DIR", empty_dir)
            .output()
            .expect("run trust-isolation test subprocess");
        assert!(
            output.status.success(),
            "trust-isolation subprocess failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    };
    let dir = PathBuf::from(dir);
    let root = std::fs::read(dir.join("root.pem")).unwrap();
    let cert = std::fs::read(dir.join("peer.pem")).unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            for version in [ProtocolVersion::Tls12, ProtocolVersion::Tls13] {
                for mode in [ClientAuthMode::Optional, ClientAuthMode::Required] {
                    for explicitly_trusted in [true, false] {
                        let client = ClientConfig::builder()
                            .with_system_root_certs()
                            .with_client_auth_pem_bytes(&cert, KEY_PEM)
                            .disable_ktls()
                            .build()
                            .unwrap();
                        let roots = if explicitly_trusted { &root } else { CERT_PEM };
                        let server = server_builder()
                            .client_auth(mode, roots)
                            .min_protocol_version(version)
                            .max_protocol_version(version)
                            .with_pem_bytes(&cert, KEY_PEM)
                            .unwrap();
                        let (client, server) = handshake(client, server).await;
                        if explicitly_trusted {
                            assert!(client.is_ok(), "default roots must verify server: {client:?}");
                            assert!(server.is_ok(), "explicit roots must verify client: {server:?}");
                        } else {
                            assert!(
                                matches!(server, Err(Error::Handshake(_))),
                                "{version:?}, {mode:?}: default roots must not verify client: {server:?}"
                            );
                        }
                    }
                }
            }
        });
}

async fn assert_rejected(client: ClientConfig, server: ServerConfig) {
    let (client, server) = handshake(client, server).await;
    assert!(client.is_err(), "client must reject the handshake");
    assert!(server.is_err(), "server must reject the handshake");
}

async fn assert_negotiated(
    client: ClientConfig,
    server: ServerConfig,
    version: &str,
    cipher: Option<&str>,
) {
    let (client, server) = handshake(client, server).await;
    for stream in [
        client.expect("client handshake"),
        server.expect("server handshake"),
    ] {
        assert!(stream.ktls_disabled());
        let negotiated = stream.negotiated();
        assert_eq!(negotiated.version(), version);
        if let Some(cipher) = cipher {
            assert_eq!(negotiated.cipher(), cipher);
        }
    }
}

#[tokio::test]
async fn client_allowlist_rejects_omitted_version_peers() {
    for (suite, omitted) in OMITTED {
        let client = client_builder().cipher_suites(&[suite]).build().unwrap();
        let server = server_builder()
            .min_protocol_version(omitted)
            .max_protocol_version(omitted)
            .with_der_bytes(&[CERT_DER], KEY_DER)
            .unwrap();
        assert_rejected(client, server).await;
    }
}

#[tokio::test]
async fn server_allowlist_rejects_omitted_version_peers() {
    for (suite, omitted) in OMITTED {
        let client = client_builder()
            .min_protocol_version(omitted)
            .max_protocol_version(omitted)
            .build()
            .unwrap();
        let server = server_builder()
            .cipher_suites(&[suite])
            .with_der_bytes(&[CERT_DER], KEY_DER)
            .unwrap();
        assert_rejected(client, server).await;
    }
}

#[tokio::test]
async fn single_version_allowlists_negotiate_only_the_listed_suite() {
    for (_, suite, version_name, cipher_name) in CASES {
        let client = client_builder().cipher_suites(&[suite]).build().unwrap();
        let server = server_builder()
            .cipher_suites(&[suite])
            .with_der_bytes(&[CERT_DER], KEY_DER)
            .unwrap();
        assert_negotiated(client, server, version_name, Some(cipher_name)).await;
    }
}

#[tokio::test]
async fn mixed_allowlists_work_for_both_versions_and_respect_bounds() {
    for (version, _, version_name, cipher_name) in CASES {
        for bound_client in [true, false] {
            let mut client = client_builder().cipher_suites(MIXED);
            let mut server = server_builder().cipher_suites(MIXED);
            // One side permits both versions, the other has an explicit
            // bound. Exercise bounds on both builders independently.
            if bound_client {
                client = client
                    .min_protocol_version(version)
                    .max_protocol_version(version);
            } else {
                server = server
                    .min_protocol_version(version)
                    .max_protocol_version(version);
            }
            assert_negotiated(
                client.build().unwrap(),
                server.with_der_bytes(&[CERT_DER], KEY_DER).unwrap(),
                version_name,
                Some(cipher_name),
            )
            .await;
        }
    }
}

#[tokio::test]
async fn empty_allowlists_restore_defaults_for_both_builders() {
    for (version, _, version_name, _) in CASES {
        for reset_client in [true, false] {
            let mut client = client_builder();
            let mut server = server_builder();
            // Start with the opposite version, then clear the override.
            let suite = if version == ProtocolVersion::Tls12 {
                TLS13_AES_128_GCM_SHA256
            } else {
                TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            };
            if reset_client {
                client = client.cipher_suites(&[suite]).cipher_suites(&[]);
                server = server
                    .min_protocol_version(version)
                    .max_protocol_version(version);
            } else {
                server = server.cipher_suites(&[suite]).cipher_suites(&[]);
                client = client
                    .min_protocol_version(version)
                    .max_protocol_version(version);
            }
            assert_negotiated(
                client.build().unwrap(),
                server.with_der_bytes(&[CERT_DER], KEY_DER).unwrap(),
                version_name,
                None,
            )
            .await;
        }
    }
}

#[tokio::test]
async fn conflicting_client_bounds_fail_without_widening() {
    let cases: &[(&[&CipherSuite], ProtocolVersion, ProtocolVersion)] = &[
        (&[MIXED[0]], ProtocolVersion::Tls13, ProtocolVersion::Tls13),
        (&[MIXED[1]], ProtocolVersion::Tls12, ProtocolVersion::Tls12),
        (MIXED, ProtocolVersion::Tls13, ProtocolVersion::Tls12),
    ];
    for &(suites, min, max) in cases {
        let client = client_builder()
            .min_protocol_version(min)
            .max_protocol_version(max)
            .cipher_suites(suites)
            .build();
        match client {
            Err(Error::Init(_)) => {} // Early validation is also safe.
            Err(error) => panic!("unexpected configuration error: {error}"),
            Ok(client) => {
                let server = server_builder()
                    .with_der_bytes(&[CERT_DER], KEY_DER)
                    .unwrap();
                assert_rejected(client, server).await;
            }
        }
    }
}

#[tokio::test]
async fn conflicting_server_bounds_fail_without_widening() {
    let cases: &[(&[&CipherSuite], ProtocolVersion, ProtocolVersion)] = &[
        (&[MIXED[0]], ProtocolVersion::Tls13, ProtocolVersion::Tls13),
        (&[MIXED[1]], ProtocolVersion::Tls12, ProtocolVersion::Tls12),
        (MIXED, ProtocolVersion::Tls13, ProtocolVersion::Tls12),
    ];
    for &(suites, min, max) in cases {
        let server = server_builder()
            .min_protocol_version(min)
            .max_protocol_version(max)
            .cipher_suites(suites)
            .with_der_bytes(&[CERT_DER], KEY_DER);
        match server {
            Err(Error::Init(_)) => {} // Early validation is also safe.
            Err(error) => panic!("unexpected configuration error: {error}"),
            Ok(server) => {
                assert_rejected(client_builder().build().unwrap(), server).await;
            }
        }
    }
}
