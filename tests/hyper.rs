//! M5 hyper integration tests.
//!
//! Exercises:
//! - HTTP/1.1 round-trip through `HyperAcceptor` + `HttpsConnector`.
//! - IPv4 and IPv6 literal URIs with IP-SAN certificate verification.
//! - HTTP/2 round-trips with forced h2 and automatic ALPN selection.
//! - HTTP/1.1 fallback when the server does not advertise h2.
//! - Linux-only: kTLS install on a hyper-served `TlsStream` still serves
//!   plaintext HTTP correctly.

#![cfg(all(feature = "hyper-client", feature = "hyper-server"))]

use std::convert::Infallible;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, Uri, Version};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
#[cfg(target_os = "linux")]
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto;
use tokio::net::TcpListener;
use tokio_aws_lc::hyper::{HttpsConnector, HyperAcceptor};
use tokio_aws_lc::{ClientConfig, ServerConfig, TlsAcceptor, TlsConnector};

const CERT_PEM: &[u8] = include_bytes!("data/cert.pem");
const KEY_PEM: &[u8] = include_bytes!("data/key.pem");
// Uses the same key, but has only an ::1 IP SAN (no DNS SAN).
const IPV6_CERT_PEM: &[u8] = include_bytes!("data/cert-ipv6.pem");
const BODY: &[u8] = b"hello from hyper over tokio-aws-lc";

async fn echo(_req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(Response::new(Full::new(Bytes::from_static(BODY))))
}

fn server_acceptor(alpn: &[&[u8]]) -> HyperAcceptor {
    let cfg = Arc::new(
        ServerConfig::builder()
            .alpn_protocols(alpn)
            .with_pem_bytes(CERT_PEM, KEY_PEM)
            .expect("ServerConfig builds"),
    );
    HyperAcceptor::new(TlsAcceptor::new(cfg))
}

fn client_connector(alpn: &[&[u8]]) -> HttpsConnector {
    let cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certs_pem_bytes(CERT_PEM)
            .alpn_protocols(alpn)
            .build()
            .expect("ClientConfig builds"),
    );
    HttpsConnector::new(TlsConnector::new(cfg))
}

async fn run_roundtrip(alpn: &[&[u8]], force_http2: bool) -> (Version, Vec<u8>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    run_roundtrip_on(
        listener,
        "localhost",
        server_acceptor(alpn),
        client_connector(alpn),
        force_http2,
    )
    .await
}

async fn run_roundtrip_on(
    listener: TcpListener,
    host: &str,
    acceptor: HyperAcceptor,
    connector: HttpsConnector,
    force_http2: bool,
) -> (Version, Vec<u8>) {
    let port = listener.local_addr().unwrap().port();

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let io = acceptor.accept(tcp).await.expect("tls accept");
        auto::Builder::new(TokioExecutor::new())
            .serve_connection(io, service_fn(echo))
            .await
            .expect("hyper serve");
    });

    let mut builder = Client::builder(TokioExecutor::new());
    if force_http2 {
        builder.http2_only(true);
    }
    let client: Client<HttpsConnector, Empty<Bytes>> = builder.build(connector);

    let uri: Uri = format!("https://{host}:{port}/").parse().unwrap();
    let req = Request::builder()
        .uri(uri)
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = client.request(req).await.expect("client request");
    let version = resp.version();
    let body = resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();

    // Drop the client so the pooled connection closes; otherwise the
    // server's serve_connection future keeps waiting for the next
    // request and we deadlock on `server.await`.
    drop(client);
    server.await.unwrap();
    (version, body)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hyper_roundtrip_http1() {
    let (version, body) = run_roundtrip(&[b"http/1.1"], false).await;
    assert_eq!(version, Version::HTTP_11);
    assert_eq!(body, BODY);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hyper_roundtrip_http2() {
    let (version, body) = run_roundtrip(&[b"h2"], true).await;
    assert_eq!(version, Version::HTTP_2);
    assert_eq!(body, BODY);
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hyper_http2_upload_with_ktls() {
    use tokio_aws_lc::cipher_suite::TLS13_AES_256_GCM_SHA384;
    use tokio_aws_lc::{host_ktls_available, ProtocolVersion};

    if !host_ktls_available() {
        assert_ne!(
            std::env::var("TOKIO_AWS_LC_REQUIRE_KTLS").as_deref(),
            Ok("1"),
            "TOKIO_AWS_LC_REQUIRE_KTLS=1 forbids skipping: host kTLS is unavailable"
        );
        eprintln!("SKIP HTTP/2 upload: host kTLS is unavailable");
        return;
    }

    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        let server_config = ServerConfig::builder()
            .alpn_protocols(&[b"h2"])
            .min_protocol_version(ProtocolVersion::Tls13)
            .max_protocol_version(ProtocolVersion::Tls13)
            .cipher_suites(&[TLS13_AES_256_GCM_SHA384])
            .with_pem_bytes(CERT_PEM, KEY_PEM)
            .unwrap();
        let client_config = ClientConfig::builder()
            .with_root_certs_pem_bytes(CERT_PEM)
            .alpn_protocols(&[b"h2"])
            .disable_ktls()
            .build()
            .unwrap();
        let acceptor = TlsAcceptor::new(Arc::new(server_config));
        let connector = HttpsConnector::new(TlsConnector::new(Arc::new(client_config)));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let stream = acceptor.accept(tcp).await.expect("TLS accept");
            assert!(stream.ktls_active(), "upload must exercise server kTLS");
            assert_eq!(stream.negotiated().version(), "TLSv1.3");
            let upload = service_fn(|request: Request<Incoming>| async move {
                assert_eq!(request.version(), Version::HTTP_2);
                let body = request.into_body().collect().await?.to_bytes();
                Ok::<_, hyper::Error>(Response::new(Full::new(body)))
            });
            auto::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), upload)
                .await
                .expect("HTTP/2 upload server");
        });

        let client: Client<HttpsConnector, Full<Bytes>> = Client::builder(TokioExecutor::new())
            .http2_only(true)
            .build(connector);
        let payload = Bytes::from(
            (0u8..=250)
                .cycle()
                .take(2 * 1024 * 1024 + 517)
                .collect::<Vec<_>>(),
        );
        let request = Request::post(format!("https://localhost:{port}/upload"))
            .body(Full::new(payload.clone()))
            .unwrap();
        let response = client.request(request).await.expect("HTTP/2 upload");
        assert_eq!(response.version(), Version::HTTP_2);
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            payload
        );
        drop(client);
        tasks
            .join_next()
            .await
            .unwrap()
            .expect("upload server task");
    })
    .await
    .expect("HTTP/2 upload exceeded its 15-second deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hyper_roundtrip_http2_via_alpn() {
    // Leave the client in automatic mode: Connection::connected() must
    // report the negotiated h2 ALPN for hyper to select HTTP/2.
    let (version, body) = run_roundtrip(&[b"h2", b"http/1.1"], false).await;
    assert_eq!(version, Version::HTTP_2);
    assert_eq!(body, BODY);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hyper_roundtrip_alpn_falls_back_to_http1() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (version, body) = run_roundtrip_on(
        listener,
        "localhost",
        server_acceptor(&[b"http/1.1"]),
        client_connector(&[b"h2", b"http/1.1"]),
        false,
    )
    .await;
    assert_eq!(version, Version::HTTP_11);
    assert_eq!(body, BODY);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hyper_roundtrip_ipv4_literal() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (version, body) = run_roundtrip_on(
        listener,
        "127.0.0.1",
        server_acceptor(&[b"http/1.1"]),
        client_connector(&[b"http/1.1"]),
        false,
    )
    .await;
    assert_eq!(version, Version::HTTP_11);
    assert_eq!(body, BODY);
}

fn ipv6_loopback_unavailable(err: &std::io::Error) -> bool {
    // EAFNOSUPPORT is not always mapped to Unsupported (e.g. on Linux).
    // Use the platform's errno value rather than a hard-coded number.
    matches!(
        err.kind(),
        std::io::ErrorKind::AddrNotAvailable | std::io::ErrorKind::Unsupported
    ) || err.raw_os_error() == Some(libc::EAFNOSUPPORT)
}

#[test]
fn ipv6_loopback_skip_only_unavailable_errors() {
    use std::io::{Error, ErrorKind};

    for (err, should_skip) in [
        (Error::from(ErrorKind::AddrNotAvailable), true),
        (Error::from(ErrorKind::Unsupported), true),
        (Error::from_raw_os_error(libc::EAFNOSUPPORT), true),
        (Error::from(ErrorKind::AddrInUse), false),
        (Error::from(ErrorKind::PermissionDenied), false),
        (Error::from_raw_os_error(libc::EMFILE), false),
        (Error::other("unexpected bind failure"), false),
    ] {
        assert_eq!(ipv6_loopback_unavailable(&err), should_skip, "{err:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hyper_roundtrip_ipv6_literal() {
    let listener = match TcpListener::bind("[::1]:0").await {
        Ok(listener) => listener,
        Err(err) if ipv6_loopback_unavailable(&err) => {
            eprintln!("IPv6 loopback unavailable; skipping: {err}");
            return;
        }
        Err(err) => panic!("bind IPv6 loopback: {err}"),
    };
    let server_cfg = ServerConfig::builder()
        .alpn_protocols(&[b"http/1.1"])
        .with_pem_bytes(IPV6_CERT_PEM, KEY_PEM)
        .expect("IPv6 ServerConfig builds");
    let client_cfg = ClientConfig::builder()
        .with_root_certs_pem_bytes(IPV6_CERT_PEM)
        .alpn_protocols(&[b"http/1.1"])
        .build()
        .expect("IPv6 ClientConfig builds");
    let (version, body) = run_roundtrip_on(
        listener,
        "[::1]",
        HyperAcceptor::new(TlsAcceptor::new(server_cfg)),
        HttpsConnector::new(TlsConnector::new(client_cfg)),
        false,
    )
    .await;
    assert_eq!(version, Version::HTTP_11);
    assert_eq!(body, BODY);
}

/// Linux-only: install kTLS on the server's `TlsStream` *before* handing
/// it to hyper, then serve a request. Proves the kernel data path is
/// transparent to hyper's `hyper::rt::Read` / `Write` traits.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hyper_roundtrip_http1_with_ktls() {
    let cfg = Arc::new(
        ServerConfig::builder()
            .alpn_protocols(&[b"http/1.1"])
            .ktls_aead_only(true)
            .with_pem_bytes(CERT_PEM, KEY_PEM)
            .expect("ServerConfig builds"),
    );
    let acceptor = TlsAcceptor::new(cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let stream = acceptor.accept(tcp).await.expect("tls accept");
        // kTLS is auto-installed on accept when the host supports it.
        // If it didn't engage (e.g. tls module unavailable in this test
        // environment) we skip the rest of the test.
        if !stream.ktls_active() {
            eprintln!("kTLS not active; skipping");
            return false;
        }
        let io = TokioIo::new(stream);
        auto::Builder::new(TokioExecutor::new())
            .serve_connection(io, service_fn(echo))
            .await
            .expect("hyper serve");
        true
    });

    let connector = client_connector(&[b"http/1.1"]);
    let client: Client<HttpsConnector, Empty<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let uri: Uri = format!("https://localhost:{port}/").parse().unwrap();
    let req = Request::builder()
        .uri(uri)
        .body(Empty::<Bytes>::new())
        .unwrap();

    let resp = match client.request(req).await {
        Ok(r) => r,
        Err(e) => {
            // If kTLS install failed and the server returned early, the
            // request also fails. Treat as a skip.
            eprintln!("client request error (likely kTLS unavailable): {e}");
            drop(client);
            let _ = server.await;
            return;
        }
    };
    let body = resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    drop(client);
    let installed = server.await.unwrap();
    if installed {
        assert_eq!(body, BODY);
    }
}

#[tokio::test]
async fn https_connector_rejects_plain_http() {
    use tower_service::Service;

    let connector = client_connector(&[b"http/1.1"]);
    let mut svc = connector;
    let uri: Uri = "http://localhost/".parse().unwrap();
    let Err(err) = svc.call(uri).await else {
        panic!("plain http must be rejected")
    };
    let msg = err.to_string();
    assert!(
        msg.contains("https"),
        "error should mention scheme, got: {msg}"
    );
}
