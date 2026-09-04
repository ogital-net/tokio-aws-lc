//! in-process round-trips: drive a real `TlsAcceptor` against a real
//! `TlsConnector` over a loopback TCP socket. Covers the plain server-
//! auth path and the mutual-TLS path.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_aws_lc::{ClientAuthMode, ClientConfig, ServerConfig, TlsAcceptor, TlsConnector};

const CERT_PEM: &[u8] = include_bytes!("data/cert.pem");
const KEY_PEM: &[u8] = include_bytes!("data/key.pem");

#[tokio::test]
async fn server_and_client_round_trip_in_process() {
    let server_cfg = Arc::new(
        ServerConfig::builder()
            .alpn_protocols(&[b"h2", b"http/1.1"])
            .with_pem_bytes(CERT_PEM, KEY_PEM)
            .expect("ServerConfig builds"),
    );
    let acceptor = TlsAcceptor::new(server_cfg);

    let client_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certs_pem_bytes(CERT_PEM)
            .alpn_protocols(&[b"h2", b"http/1.1"])
            .build()
            .expect("ClientConfig builds"),
    );
    let connector = TlsConnector::new(client_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(tcp).await.expect("server handshake");
        stream
            .write_all(b"ping from server")
            .await
            .expect("server write");
        let mut buf = [0u8; 32];
        let n = stream.read(&mut buf).await.expect("server read");
        let echoed = &buf[..n];
        assert_eq!(echoed, b"pong from client");
        let negotiated = stream.negotiated();
        // RFC 5705 keying-material exporter — exercise both the
        // context-less and contextual paths and compare against the
        // peer at the end of the test.
        let mut ekm_no_ctx = [0u8; 32];
        stream
            .export_keying_material(&mut ekm_no_ctx, b"EXPORTER-test", None)
            .expect("server EKM no-ctx");
        let mut ekm_ctx = [0u8; 32];
        stream
            .export_keying_material(&mut ekm_ctx, b"EXPORTER-test", Some(b"ctx"))
            .expect("server EKM with-ctx");
        assert_ne!(ekm_no_ctx, ekm_ctx, "context vs no-context EKM must differ");
        stream.shutdown().await.ok();
        (negotiated, ekm_no_ctx, ekm_ctx)
    });

    let client = tokio::spawn(async move {
        let tcp = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("tcp connect");
        let mut stream = connector
            .connect("localhost", tcp)
            .await
            .expect("client handshake");
        let mut buf = [0u8; 32];
        let n = stream.read(&mut buf).await.expect("client read");
        assert_eq!(&buf[..n], b"ping from server");
        stream
            .write_all(b"pong from client")
            .await
            .expect("client write");
        let negotiated = stream.negotiated();
        let mut ekm_no_ctx = [0u8; 32];
        stream
            .export_keying_material(&mut ekm_no_ctx, b"EXPORTER-test", None)
            .expect("client EKM no-ctx");
        let mut ekm_ctx = [0u8; 32];
        stream
            .export_keying_material(&mut ekm_ctx, b"EXPORTER-test", Some(b"ctx"))
            .expect("client EKM with-ctx");
        stream.shutdown().await.ok();
        (negotiated, ekm_no_ctx, ekm_ctx)
    });

    let (server_neg, server_ekm_no_ctx, server_ekm_ctx) = server.await.unwrap();
    let (client_neg, client_ekm_no_ctx, client_ekm_ctx) = client.await.unwrap();

    assert!(server_neg.version().starts_with("TLSv1"));
    assert!(client_neg.version().starts_with("TLSv1"));
    assert_eq!(server_neg.alpn(), Some(b"h2".as_slice()));
    assert_eq!(client_neg.alpn(), Some(b"h2".as_slice()));
    assert_eq!(server_neg.sni(), Some("localhost"));
    assert_eq!(server_neg.cipher(), client_neg.cipher());
    assert_eq!(server_neg.version(), client_neg.version());
    // RFC 5705: both sides derive the same exporter output.
    assert_eq!(server_ekm_no_ctx, client_ekm_no_ctx);
    assert_eq!(server_ekm_ctx, client_ekm_ctx);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_survives_peer_dropping_socket_without_close_notify() {
    let server_cfg = Arc::new(
        ServerConfig::builder()
            .with_pem_bytes(CERT_PEM, KEY_PEM)
            .expect("ServerConfig builds"),
    );
    let acceptor = TlsAcceptor::new(server_cfg);

    let client_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certs_pem_bytes(CERT_PEM)
            .build()
            .expect("ClientConfig builds"),
    );
    let connector = TlsConnector::new(client_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let (peer_gone_tx, peer_gone_rx) = tokio::sync::oneshot::channel::<()>();

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(tcp).await.expect("server handshake");
        stream
            .write_all(b"last message before close")
            .await
            .expect("server write");
        // Wait for the client to abort its TCP socket before shutting
        // down, so the server observes a deterministic EOF race.
        peer_gone_rx.await.expect("client signaled abort");
        stream
            .shutdown()
            .await
            .expect("server shutdown must succeed");
    });

    let client = tokio::spawn(async move {
        let tcp = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("tcp connect");
        // SO_LINGER=0 turns the drop below into a TCP RST, so the peer
        // observes an EOF before any close_notify is sent.
        tcp.set_zero_linger().expect("set SO_LINGER=0");
        let mut stream = connector
            .connect("localhost", tcp)
            .await
            .expect("client handshake");
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.expect("client read");
        assert_eq!(&buf[..n], b"last message before close");
        // Drop without shutdown so the RST fires immediately.
        drop(stream);
        // Give the RST a moment to actually leave the kernel's send
        // queue before telling the server it's safe to proceed.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let _ = peer_gone_tx.send(());
    });

    client.await.expect("client task");
    server.await.expect("server task");
}

#[tokio::test]
async fn mutual_tls_required_round_trip() {
    let server_cfg = Arc::new(
        ServerConfig::builder()
            .client_auth(ClientAuthMode::Required, CERT_PEM)
            .with_pem_bytes(CERT_PEM, KEY_PEM)
            .expect("mTLS-required ServerConfig builds"),
    );
    let acceptor = TlsAcceptor::new(server_cfg);

    let client_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certs_pem_bytes(CERT_PEM)
            .with_client_auth_pem_bytes(CERT_PEM, KEY_PEM)
            .build()
            .expect("mTLS ClientConfig builds"),
    );
    let connector = TlsConnector::new(client_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let stream = acceptor.accept(tcp).await.expect("server handshake");
        assert!(
            stream.has_peer_certificate(),
            "server should have received a client cert"
        );
    });

    let client = tokio::spawn(async move {
        let tcp = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("tcp connect");
        let stream = connector
            .connect("localhost", tcp)
            .await
            .expect("client handshake");
        assert!(
            stream.has_peer_certificate(),
            "client should have received a server cert"
        );
    });

    server.await.unwrap();
    client.await.unwrap();
}

#[tokio::test]
async fn mtls_required_but_client_offers_no_cert_fails() {
    let server_cfg = Arc::new(
        ServerConfig::builder()
            .client_auth(ClientAuthMode::Required, CERT_PEM)
            .with_pem_bytes(CERT_PEM, KEY_PEM)
            .expect("mTLS-required ServerConfig builds"),
    );
    let acceptor = TlsAcceptor::new(server_cfg);

    // Client offers no client cert.
    let client_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certs_pem_bytes(CERT_PEM)
            .build()
            .expect("client config builds"),
    );
    let connector = TlsConnector::new(client_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        // Handshake should fail because the client didn't send a cert.
        let res = acceptor.accept(tcp).await;
        assert!(res.is_err(), "server handshake should have failed");
    });

    let client = tokio::spawn(async move {
        let tcp = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("tcp connect");
        // Client side may or may not surface this as an error before the
        // server closes the connection; we don't assert success here.
        let _ = connector.connect("localhost", tcp).await;
    });

    server.await.unwrap();
    client.await.unwrap();
}

#[tokio::test]
async fn hostname_verification_rejects_wrong_name() {
    let server_cfg = Arc::new(
        ServerConfig::builder()
            .with_pem_bytes(CERT_PEM, KEY_PEM)
            .expect("ServerConfig builds"),
    );
    let acceptor = TlsAcceptor::new(server_cfg);

    let client_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certs_pem_bytes(CERT_PEM)
            .build()
            .expect("ClientConfig builds"),
    );
    let connector = TlsConnector::new(client_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let _server = tokio::spawn(async move {
        if let Ok((tcp, _)) = listener.accept().await {
            // We expect the server to error out because the client will
            // bail when the cert (CN=localhost) doesn't match the
            // requested name (not.localhost).
            let _ = acceptor.accept(tcp).await;
        }
    });

    let tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("tcp connect");
    let res = connector.connect("not.localhost", tcp).await;
    assert!(
        res.is_err(),
        "client handshake should reject a mismatched hostname"
    );
}

#[tokio::test]
async fn cipher_suite_pin_tls13_aes256() {
    use tokio_aws_lc::cipher_suite::TLS13_AES_256_GCM_SHA384;

    let server_cfg = Arc::new(
        ServerConfig::builder()
            .cipher_suites(&[TLS13_AES_256_GCM_SHA384])
            .with_pem_bytes(CERT_PEM, KEY_PEM)
            .expect("ServerConfig builds"),
    );
    let acceptor = TlsAcceptor::new(server_cfg);

    let client_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certs_pem_bytes(CERT_PEM)
            .cipher_suites(&[TLS13_AES_256_GCM_SHA384])
            .build()
            .expect("ClientConfig builds"),
    );
    let connector = TlsConnector::new(client_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(tcp).await.expect("server handshake");
        let neg = stream.negotiated();
        assert_eq!(neg.cipher(), "TLS_AES_256_GCM_SHA384");
        stream.shutdown().await.ok();
    });

    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut stream = connector
        .connect("localhost", tcp)
        .await
        .expect("client handshake");
    let neg = stream.negotiated();
    assert_eq!(neg.version(), "TLSv1.3");
    assert_eq!(neg.cipher(), "TLS_AES_256_GCM_SHA384");
    stream.shutdown().await.ok();
    server.await.unwrap();
}

#[tokio::test]
async fn cipher_suite_pin_mismatch_fails_handshake() {
    use tokio_aws_lc::cipher_suite::{TLS13_AES_128_GCM_SHA256, TLS13_CHACHA20_POLY1305_SHA256};

    let server_cfg = Arc::new(
        ServerConfig::builder()
            .max_protocol_version(tokio_aws_lc::ProtocolVersion::Tls13)
            .min_protocol_version(tokio_aws_lc::ProtocolVersion::Tls13)
            .cipher_suites(&[TLS13_AES_128_GCM_SHA256])
            .with_pem_bytes(CERT_PEM, KEY_PEM)
            .expect("ServerConfig builds"),
    );
    let acceptor = TlsAcceptor::new(server_cfg);

    let client_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certs_pem_bytes(CERT_PEM)
            .max_protocol_version(tokio_aws_lc::ProtocolVersion::Tls13)
            .min_protocol_version(tokio_aws_lc::ProtocolVersion::Tls13)
            .cipher_suites(&[TLS13_CHACHA20_POLY1305_SHA256])
            .build()
            .expect("ClientConfig builds"),
    );
    let connector = TlsConnector::new(client_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let _server = tokio::spawn(async move {
        if let Ok((tcp, _)) = listener.accept().await {
            let _ = acceptor.accept(tcp).await;
        }
    });

    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let res = connector.connect("localhost", tcp).await;
    assert!(
        res.is_err(),
        "non-overlapping TLS 1.3 cipher pin should kill the handshake"
    );
}

#[tokio::test]
async fn cipher_suite_pin_tls12_aead() {
    use tokio_aws_lc::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
    use tokio_aws_lc::ProtocolVersion;

    let server_cfg = Arc::new(
        ServerConfig::builder()
            .min_protocol_version(ProtocolVersion::Tls12)
            .max_protocol_version(ProtocolVersion::Tls12)
            .cipher_suites(&[TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256])
            .with_pem_bytes(CERT_PEM, KEY_PEM)
            .expect("ServerConfig builds"),
    );
    let acceptor = TlsAcceptor::new(server_cfg);

    let client_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certs_pem_bytes(CERT_PEM)
            .min_protocol_version(ProtocolVersion::Tls12)
            .max_protocol_version(ProtocolVersion::Tls12)
            .cipher_suites(&[TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256])
            .build()
            .expect("ClientConfig builds"),
    );
    let connector = TlsConnector::new(client_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(tcp).await.expect("server handshake");
        let neg = stream.negotiated();
        assert_eq!(neg.version(), "TLSv1.2");
        assert_eq!(neg.cipher(), "ECDHE-ECDSA-AES128-GCM-SHA256");
        stream.shutdown().await.ok();
    });

    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut stream = connector
        .connect("localhost", tcp)
        .await
        .expect("client handshake");
    let neg = stream.negotiated();
    assert_eq!(neg.version(), "TLSv1.2");
    assert_eq!(neg.cipher(), "ECDHE-ECDSA-AES128-GCM-SHA256");
    stream.shutdown().await.ok();
    server.await.unwrap();
}

/// System trust store does not include our self-signed fixture, so a
/// client built without a custom root bundle must reject the server.
#[tokio::test]
async fn client_rejects_untrusted_server_cert() {
    let server_cfg = Arc::new(
        ServerConfig::builder()
            .with_pem_bytes(CERT_PEM, KEY_PEM)
            .expect("ServerConfig builds"),
    );
    let acceptor = TlsAcceptor::new(server_cfg);

    // No `with_root_certs_pem_bytes` — falls through to system roots,
    // which (in CI and locally) do not trust our self-signed cert.
    let client_cfg = Arc::new(
        ClientConfig::builder()
            .build()
            .expect("ClientConfig builds"),
    );
    let connector = TlsConnector::new(client_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let _server = tokio::spawn(async move {
        if let Ok((tcp, _)) = listener.accept().await {
            // Server may or may not see the handshake error before the
            // client tears down the connection; either outcome is fine.
            let _ = acceptor.accept(tcp).await;
        }
    });

    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let res = connector.connect("localhost", tcp).await;
    assert!(
        res.is_err(),
        "client should reject a server cert not in the system trust store"
    );
}

/// `dangerous_disable_verification` is the documented escape hatch for
/// test scenarios. Verify it actually disables verification (otherwise
/// the method is a footgun without the foot).
#[tokio::test]
async fn dangerous_disable_verification_accepts_untrusted() {
    let server_cfg = Arc::new(
        ServerConfig::builder()
            .with_pem_bytes(CERT_PEM, KEY_PEM)
            .expect("ServerConfig builds"),
    );
    let acceptor = TlsAcceptor::new(server_cfg);

    let client_cfg = Arc::new(
        ClientConfig::builder()
            .dangerous_disable_verification()
            .build()
            .expect("ClientConfig builds"),
    );
    let connector = TlsConnector::new(client_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(tcp).await.expect("server handshake");
        stream.shutdown().await.ok();
    });

    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    // Use a hostname that wouldn't pass verification either — the
    // dangerous mode must skip both chain validation *and* hostname
    // checks.
    let mut stream = connector
        .connect("not.localhost", tcp)
        .await
        .expect("handshake should succeed with verification disabled");
    stream.shutdown().await.ok();
    server.await.unwrap();
}

/// `ClientAuthMode::Optional` requests a client cert but accepts a
/// handshake without one.
#[tokio::test]
async fn mtls_optional_accepts_client_without_cert() {
    let server_cfg = Arc::new(
        ServerConfig::builder()
            .client_auth(ClientAuthMode::Optional, CERT_PEM)
            .with_pem_bytes(CERT_PEM, KEY_PEM)
            .expect("mTLS-optional ServerConfig builds"),
    );
    let acceptor = TlsAcceptor::new(server_cfg);

    let client_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certs_pem_bytes(CERT_PEM)
            .build()
            .expect("ClientConfig builds"),
    );
    let connector = TlsConnector::new(client_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let stream = acceptor
            .accept(tcp)
            .await
            .expect("server handshake should succeed without client cert");
        assert!(
            !stream.has_peer_certificate(),
            "client did not send a cert, so the server should not see one"
        );
    });

    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut stream = connector
        .connect("localhost", tcp)
        .await
        .expect("client handshake should succeed");
    stream.shutdown().await.ok();
    server.await.unwrap();
}

/// When `ClientAuthMode::Required` is in effect, the server's client-CA
/// trust store must contain *only* the explicitly provided private CA
/// roots — not the system trust store. A client presenting a cert that
/// is neither in the configured roots nor signed by them must be
/// rejected, even if it would be accepted by the host's system CAs.
///
/// This guards against a regression where someone "helpfully" calls
/// `SSL_CTX_set_default_verify_paths` on the server CTX during build:
/// that would silently widen the trust set on the client-auth path.
#[tokio::test]
async fn mtls_required_rejects_cert_outside_private_roots() {
    // Cert + key independent of CERT_PEM/KEY_PEM. Self-signed P-256;
    // CN=other.invalid; not present in the server's client-CA roots.
    const OTHER_CERT_PEM: &[u8] = include_bytes!("data/cert2.pem");
    const OTHER_KEY_PEM: &[u8] = include_bytes!("data/cert2-key.pem");

    // Server trusts only CERT_PEM as a client CA root.
    let server_cfg = Arc::new(
        ServerConfig::builder()
            .client_auth(ClientAuthMode::Required, CERT_PEM)
            .with_pem_bytes(CERT_PEM, KEY_PEM)
            .expect("mTLS-required ServerConfig builds"),
    );
    let acceptor = TlsAcceptor::new(server_cfg);

    // Client presents OTHER_CERT_PEM, signed by neither CERT_PEM nor
    // any real CA the host might know about.
    let client_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certs_pem_bytes(CERT_PEM)
            .with_client_auth_pem_bytes(OTHER_CERT_PEM, OTHER_KEY_PEM)
            .build()
            .expect("ClientConfig builds"),
    );
    let connector = TlsConnector::new(client_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let res = acceptor.accept(tcp).await;
        assert!(
            res.is_err(),
            "server handshake should have failed (client cert outside configured roots)"
        );
    });

    let client = tokio::spawn(async move {
        let tcp = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("tcp connect");
        // In TLS 1.3 mutual auth the client can finish its handshake
        // before the server has processed the client's certificate, so
        // `connect()` itself may succeed — the alert arrives on the
        // next read. Either path is acceptable; what we forbid is a
        // successful read/write round-trip with an untrusted client
        // cert.
        match connector.connect("localhost", tcp).await {
            Err(_) => {}
            Ok(mut stream) => {
                let _ = stream.write_all(b"ping").await;
                let mut buf = [0u8; 16];
                let res = stream.read(&mut buf).await;
                match res {
                    Err(_) | Ok(0) => {} // error or peer closed without bytes
                    Ok(_) => panic!(
                        "client read should not have succeeded with an untrusted client cert"
                    ),
                }
            }
        }
    });

    server.await.unwrap();
    client.await.unwrap();
}

// ---------------------------------------------------------------------
// Targeted contracts on `TlsConnector::connect`:
//   * empty server_name is rejected up-front,
//   * IP literals route through X509 iPAddress SAN matching rather than
//     SNI + DNS-SAN matching (RFC 6066 §3),
//   * ALPN mismatch fails the handshake with a fatal alert instead of
//     silently completing with no negotiated protocol.
// ---------------------------------------------------------------------

#[tokio::test]
async fn connect_rejects_empty_server_name() {
    let client_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certs_pem_bytes(CERT_PEM)
            .build()
            .expect("ClientConfig builds"),
    );
    let connector = TlsConnector::new(client_cfg);

    // We never actually open a TCP connection — the empty-name check
    // happens before any FD work — but `connect` takes ownership of a
    // TcpStream, so synthesise one with a never-connecting listener.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();

    let err = connector
        .connect("", tcp)
        .await
        .expect_err("empty server_name must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("server_name") && msg.contains("empty"),
        "got: {msg}"
    );
}

#[tokio::test]
async fn connect_with_ip_literal_uses_ip_san() {
    // The test cert at tests/data/cert.pem carries
    //   subjectAltName = DNS:localhost, IP:127.0.0.1
    // so an IP-literal connect should authenticate against the IP SAN
    // even though SNI is suppressed for IP peers.
    let server_cfg = Arc::new(
        ServerConfig::builder()
            .with_pem_bytes(CERT_PEM, KEY_PEM)
            .expect("ServerConfig builds"),
    );
    let acceptor = TlsAcceptor::new(server_cfg);

    let client_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certs_pem_bytes(CERT_PEM)
            .build()
            .expect("ClientConfig builds"),
    );
    let connector = TlsConnector::new(client_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(tcp).await.expect("server handshake");
        stream.write_all(b"ip-ok").await.expect("server write");
        stream.shutdown().await.ok();
    });

    let client = tokio::spawn(async move {
        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut stream = connector
            .connect("127.0.0.1", tcp)
            .await
            .expect("client handshake with IP literal");
        let mut buf = [0u8; 8];
        let n = stream.read(&mut buf).await.expect("client read");
        assert_eq!(&buf[..n], b"ip-ok");
    });

    server.await.unwrap();
    client.await.unwrap();
}

#[tokio::test]
async fn connect_with_unknown_ip_san_fails() {
    // The cert has IP:127.0.0.1 but no IP:127.0.0.2; even though we
    // dial loopback we ask the verifier to bind the peer to 127.0.0.2,
    // which must fail.
    let server_cfg = Arc::new(
        ServerConfig::builder()
            .with_pem_bytes(CERT_PEM, KEY_PEM)
            .expect("ServerConfig builds"),
    );
    let acceptor = TlsAcceptor::new(server_cfg);

    let client_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certs_pem_bytes(CERT_PEM)
            .build()
            .expect("ClientConfig builds"),
    );
    let connector = TlsConnector::new(client_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = tokio::spawn(async move {
        if let Ok((tcp, _)) = listener.accept().await {
            // Best-effort: the handshake will fail; just drop.
            let _ = acceptor.accept(tcp).await;
        }
    });

    let client = tokio::spawn(async move {
        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let err = connector
            .connect("127.0.0.2", tcp)
            .await
            .expect_err("handshake must fail when IP SAN does not match");
        let msg = format!("{err}");
        assert!(
            msg.contains("handshake") || msg.contains("verify"),
            "got: {msg}"
        );
    });

    let _ = server.await;
    client.await.unwrap();
}

#[tokio::test]
async fn alpn_mismatch_fails_handshake_with_fatal_alert() {
    let server_cfg = Arc::new(
        ServerConfig::builder()
            .alpn_protocols(&[b"h2"])
            .with_pem_bytes(CERT_PEM, KEY_PEM)
            .expect("ServerConfig builds"),
    );
    let acceptor = TlsAcceptor::new(server_cfg);

    let client_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certs_pem_bytes(CERT_PEM)
            .alpn_protocols(&[b"h3"]) // disjoint from server
            .build()
            .expect("ClientConfig builds"),
    );
    let connector = TlsConnector::new(client_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = tokio::spawn(async move {
        if let Ok((tcp, _)) = listener.accept().await {
            // Expect failure; we don't care about the details on this side.
            let _ = acceptor.accept(tcp).await;
        }
    });

    let client = tokio::spawn(async move {
        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let err = connector
            .connect("localhost", tcp)
            .await
            .expect_err("ALPN mismatch must abort the handshake");
        let msg = format!("{err}");
        // Either the alert text mentions "no_application_protocol" or
        // the handshake error is surfaced — both are acceptable; we
        // just don't want a silent success.
        assert!(
            msg.to_lowercase().contains("handshake")
                || msg.to_lowercase().contains("alert")
                || msg.to_lowercase().contains("alpn"),
            "got: {msg}"
        );
    });

    let _ = server.await;
    client.await.unwrap();
}
