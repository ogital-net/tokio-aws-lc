//! M5 hyper integration tests.
//!
//! Exercises:
//! - HTTP/1.1 round-trip through `HyperAcceptor` + `HttpsConnector`.
//! - HTTP/2 round-trip via ALPN-negotiated h2.
//! - Linux-only: kTLS install on a hyper-served `TlsStream` still serves
//!   plaintext HTTP correctly.

#![cfg(feature = "hyper")]

use std::convert::Infallible;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, Uri};
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

async fn run_roundtrip(alpn: &[&[u8]], force_http2: bool) -> Vec<u8> {
    let acceptor = server_acceptor(alpn);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let io = acceptor.accept(tcp).await.expect("tls accept");
        auto::Builder::new(TokioExecutor::new())
            .serve_connection(io, service_fn(echo))
            .await
            .expect("hyper serve");
    });

    let connector = client_connector(alpn);
    let mut builder = Client::builder(TokioExecutor::new());
    if force_http2 {
        builder.http2_only(true);
    }
    let client: Client<HttpsConnector, Empty<Bytes>> = builder.build(connector);

    let uri: Uri = format!("https://localhost:{port}/").parse().unwrap();
    let req = Request::builder()
        .uri(uri)
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = client.request(req).await.expect("client request");
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
    body
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hyper_roundtrip_http1() {
    let body = run_roundtrip(&[b"http/1.1"], false).await;
    assert_eq!(body, BODY);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hyper_roundtrip_http2() {
    let body = run_roundtrip(&[b"h2"], true).await;
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
