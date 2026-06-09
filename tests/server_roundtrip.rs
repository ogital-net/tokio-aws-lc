//! M2 wire-level test: drive `openssl s_client` against a real
//! `TlsAcceptor` and verify the handshake + server-initiated write +
//! shutdown all work end-to-end.
//!
//! Skips gracefully when `openssl` isn't on PATH so the suite stays green
//! on minimal CI images. CI itself is expected to have OpenSSL 3.x.

use std::process::Stdio;
use std::sync::Arc;

use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio_aws_lc::{ServerConfig, TlsAcceptor};

const CERT_PEM: &[u8] = include_bytes!("data/cert.pem");
const KEY_PEM: &[u8] = include_bytes!("data/key.pem");

#[tokio::test]
async fn handshake_and_server_write_against_openssl_s_client() {
    if !openssl_available().await {
        eprintln!("skipping: openssl binary not available on PATH");
        return;
    }

    let cfg = Arc::new(
        ServerConfig::builder()
            .alpn_protocols(&[b"h2", b"http/1.1"])
            .with_pem_bytes(CERT_PEM, KEY_PEM)
            .expect("ServerConfig builds"),
    );
    let acceptor = TlsAcceptor::new(cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    // Server task: accept one TLS connection, write a greeting, close.
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(tcp).await.expect("server handshake");

        let negotiated = stream.negotiated();
        assert!(
            negotiated.version().starts_with("TLSv1"),
            "unexpected version: {}",
            negotiated.version()
        );

        stream
            .write_all(b"hello from tokio-aws-lc\n")
            .await
            .expect("server write");
        stream.shutdown().await.expect("server shutdown");
        negotiated
    });

    // Client: openssl s_client.
    let cert_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/cert.pem");
    let mut cmd = Command::new("openssl");
    cmd.args([
        "s_client",
        "-connect",
        &format!("127.0.0.1:{port}"),
        "-CAfile",
        cert_path,
        "-servername",
        "localhost",
        "-verify_return_error",
        "-quiet",
        "-alpn",
        "h2,http/1.1",
    ])
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());

    let output = cmd
        .spawn()
        .expect("spawn openssl")
        .wait_with_output()
        .await
        .expect("openssl exited cleanly (or with output)");

    let negotiated = server.await.expect("server task");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("hello from tokio-aws-lc"),
        "openssl stdout did not contain greeting.\nstdout: {stdout}\nstderr: {stderr}\nnegotiated: {negotiated:?}"
    );

    // ALPN sanity: we offered h2 and http/1.1; the server should select
    // the first match (h2).
    assert_eq!(
        negotiated.alpn(),
        Some(b"h2".as_slice()),
        "expected ALPN=h2"
    );

    // SNI sanity: openssl sends "localhost".
    assert_eq!(negotiated.sni(), Some("localhost"));
}

async fn openssl_available() -> bool {
    Command::new("openssl")
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .is_ok_and(|s| s.success())
}
