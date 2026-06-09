//! Linux-only kTLS integration test.
//!
//! Drives a real in-process TLS handshake, then installs kTLS on both
//! sides and exchanges plaintext through the kernel `tls` ULP. The
//! kernel's `/proc/net/tls_stat` counters are sampled before/after to
//! confirm the data actually flowed through `TlsSw` (the kernel
//! software kTLS path) rather than userspace AEAD.
//!
//! The test self-skips on:
//! - non-Linux targets (compiled out entirely),
//! - kernels where `/proc/net/tls_stat` does not exist (no kTLS
//!   support compiled in or the `tls` module is not loaded),
//! - kernels that reject `setsockopt(SOL_TCP, TCP_ULP, "tls")`
//!   ([`KtlsError::TlsUlpUnavailable`]), or
//! - kernels that accept the ULP but refuse the per-direction
//!   crypto-info upload ([`KtlsError::SetSockOpt`]).

#![cfg(target_os = "linux")]

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_aws_lc::{
    host_ktls_available, ClientConfig, Error, KtlsError, ProtocolVersion, ServerConfig,
    TlsAcceptor, TlsConnector,
};

const CERT_PEM: &[u8] = include_bytes!("data/cert.pem");
const KEY_PEM: &[u8] = include_bytes!("data/key.pem");

/// Sum of `TlsTxSw` and `TlsRxSw` counters from `/proc/net/tls_stat`.
/// Returns `None` if the file does not exist (older kernel or `tls`
/// module not loaded).
fn read_tls_sw_counters() -> Option<(u64, u64)> {
    let text = std::fs::read_to_string("/proc/net/tls_stat").ok()?;
    let mut tx = None;
    let mut rx = None;
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let key = it.next()?;
        let val: u64 = it.next()?.parse().ok()?;
        match key {
            "TlsTxSw" => tx = Some(val),
            "TlsRxSw" => rx = Some(val),
            _ => {}
        }
    }
    Some((tx?, rx?))
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn ktls_install_and_round_trip() {
    if !host_ktls_available() {
        println!("skipping: host_ktls_available() == false");
        return;
    }
    let Some(pre) = read_tls_sw_counters() else {
        println!("skipping: /proc/net/tls_stat unavailable");
        return;
    };

    let server_cfg = Arc::new(
        ServerConfig::builder()
            .ktls_aead_only(true)
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
        let mut stream = match acceptor.accept(tcp).await {
            Ok(s) => s,
            Err(Error::Ktls(KtlsError::SetSockOpt(e))) => {
                return Err(format!("server kTLS setsockopt: {e}"));
            }
            Err(e) => return Err(format!("server handshake: {e}")),
        };
        if !stream.ktls_active() {
            return Err("server kTLS did not engage".to_string());
        }
        // Without mTLS the server has no peer certificate.
        assert!(
            !stream.has_peer_certificate(),
            "server has_peer_certificate should be false"
        );
        // Move some bytes plaintext-through-kernel both ways.
        stream
            .write_all(b"hello from kernel-tls server")
            .await
            .expect("server write");
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.expect("server read");
        assert_eq!(&buf[..n], b"hello from kernel-tls client");
        // Don't call SSL_shutdown after kTLS install — the kernel TX
        // path would corrupt the alert. The kTLS-aware poll_shutdown
        // does the right thing (shutdown(SHUT_WR)).
        stream.shutdown().await.ok();
        Ok(())
    });

    let client = tokio::spawn(async move {
        let tcp = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("client tcp connect");
        let mut stream = match connector.connect("localhost", tcp).await {
            Ok(s) => s,
            Err(Error::Ktls(KtlsError::SetSockOpt(e))) => {
                return Err(format!("client kTLS setsockopt: {e}"));
            }
            Err(e) => return Err(format!("client handshake: {e}")),
        };
        if !stream.ktls_active() {
            return Err("client kTLS did not engage".to_string());
        }
        // Client always sees the server's certificate.
        assert!(
            stream.has_peer_certificate(),
            "client has_peer_certificate should be true"
        );
        stream
            .write_all(b"hello from kernel-tls client")
            .await
            .expect("client write");
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.expect("client read");
        assert_eq!(&buf[..n], b"hello from kernel-tls server");
        stream.shutdown().await.ok();
        Ok(())
    });

    let s = server.await.unwrap();
    let c = client.await.unwrap();
    if let Err(e) = &s {
        if e.contains("setsockopt") || e.contains("did not engage") {
            println!("skipping: kernel kTLS install failed: {e}");
            return;
        }
    }
    if let Err(e) = &c {
        if e.contains("setsockopt") || e.contains("did not engage") {
            println!("skipping: kernel kTLS install failed: {e}");
            return;
        }
    }
    s.expect("server task ok");
    c.expect("client task ok");

    let after = read_tls_sw_counters().expect("counters still readable");
    let dtx = after.0.saturating_sub(pre.0);
    let drx = after.1.saturating_sub(pre.1);
    // Both endpoints did kTLS, so TX should have advanced at least
    // twice (one per endpoint) and RX likewise. We assert >= 2 of each
    // rather than == to remain robust against any unrelated TLS
    // traffic on the host during the test window.
    assert!(
        dtx >= 2,
        "TlsTxSw counter did not advance: pre={} after={}",
        pre.0,
        after.0
    );
    assert!(
        drx >= 2,
        "TlsRxSw counter did not advance: pre={} after={}",
        pre.1,
        after.1
    );
}

#[tokio::test]
async fn ktls_eligibility_reports_aead_compatible() {
    let server_cfg = Arc::new(
        ServerConfig::builder()
            .ktls_aead_only(true)
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
        let stream = acceptor.accept(tcp).await.expect("server handshake");
        let elig = stream.ktls_eligibility();
        assert!(
            elig.is_compatible(),
            "negotiated session must be ktls-compatible: {elig:?}"
        );
        elig
    });
    let client = tokio::spawn(async move {
        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let stream = connector
            .connect("localhost", tcp)
            .await
            .expect("client handshake");
        let elig = stream.ktls_eligibility();
        assert!(elig.is_compatible(), "client side: {elig:?}");
        elig
    });
    let s = server.await.unwrap();
    let c = client.await.unwrap();
    assert_eq!(s.tls_version(), c.tls_version());
    assert_eq!(s.cipher(), c.cipher());
}

/// Pin both ends to TLS 1.2 + AEAD-only ciphers and round-trip plaintext
/// through the kernel `tls` ULP. Exercises the TLS 1.2 branch in
/// `derive_crypto_info` (key-block reader, `is_server`, server-perspective
/// split) which the TLS 1.3 default path doesn't touch.
#[tokio::test]
async fn ktls_install_and_round_trip_tls12() {
    if read_tls_sw_counters().is_none() {
        println!("skipping: /proc/net/tls_stat unavailable");
        return;
    }

    let server_cfg = Arc::new(
        ServerConfig::builder()
            .min_protocol_version(ProtocolVersion::Tls12)
            .max_protocol_version(ProtocolVersion::Tls12)
            .ktls_aead_only(true)
            .with_pem_bytes(CERT_PEM, KEY_PEM)
            .expect("ServerConfig builds (TLS 1.2)"),
    );
    let acceptor = TlsAcceptor::new(server_cfg);

    let client_cfg = Arc::new(
        ClientConfig::builder()
            .min_protocol_version(ProtocolVersion::Tls12)
            .max_protocol_version(ProtocolVersion::Tls12)
            .with_root_certs_pem_bytes(CERT_PEM)
            .build()
            .expect("ClientConfig builds (TLS 1.2)"),
    );
    let connector = TlsConnector::new(client_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut stream = match acceptor.accept(tcp).await {
            Ok(s) => s,
            Err(Error::Ktls(KtlsError::SetSockOpt(e))) => {
                return Err(format!("server kTLS setsockopt: {e}"));
            }
            Err(e) => return Err(format!("server handshake: {e}")),
        };
        assert_eq!(stream.negotiated().version(), "TLSv1.2");
        if !stream.ktls_active() {
            return Err("server kTLS did not engage".to_string());
        }
        stream
            .write_all(b"tls12 server hello")
            .await
            .expect("server write");
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.expect("server read");
        assert_eq!(&buf[..n], b"tls12 client hello");
        stream.shutdown().await.ok();
        Ok(())
    });

    let client = tokio::spawn(async move {
        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut stream = match connector.connect("localhost", tcp).await {
            Ok(s) => s,
            Err(Error::Ktls(KtlsError::SetSockOpt(e))) => {
                return Err(format!("client kTLS setsockopt: {e}"));
            }
            Err(e) => return Err(format!("client handshake: {e}")),
        };
        assert_eq!(stream.negotiated().version(), "TLSv1.2");
        if !stream.ktls_active() {
            return Err("client kTLS did not engage".to_string());
        }
        stream
            .write_all(b"tls12 client hello")
            .await
            .expect("client write");
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.expect("client read");
        assert_eq!(&buf[..n], b"tls12 server hello");
        stream.shutdown().await.ok();
        Ok(())
    });

    let s = server.await.unwrap();
    let c = client.await.unwrap();
    if let Err(e) = &s {
        if e.contains("setsockopt") || e.contains("did not engage") {
            println!("skipping: kernel rejected TLS 1.2 kTLS install: {e}");
            return;
        }
    }
    if let Err(e) = &c {
        if e.contains("setsockopt") || e.contains("did not engage") {
            println!("skipping: kernel rejected TLS 1.2 kTLS install: {e}");
            return;
        }
    }
    s.expect("server task ok");
    c.expect("client task ok");
}

/// Build a server+client pair pinned to a single TLS 1.3 cipher, run
/// `install_ktls()` on both sides, and round-trip one message each way.
/// Used to exercise the AES-256 and `ChaCha20` arms in
/// `src/ktls/mod.rs::derive_crypto_info`.
async fn run_tls13_ktls_round_trip(
    suite: &'static tokio_aws_lc::CipherSuite,
    expected_iana_name: &str,
) {
    if read_tls_sw_counters().is_none() {
        println!("skipping: /proc/net/tls_stat unavailable");
        return;
    }

    let server_cfg = Arc::new(
        ServerConfig::builder()
            .min_protocol_version(ProtocolVersion::Tls13)
            .max_protocol_version(ProtocolVersion::Tls13)
            .cipher_suites(&[suite])
            .with_pem_bytes(CERT_PEM, KEY_PEM)
            .expect("ServerConfig builds (TLS 1.3 pinned)"),
    );
    let acceptor = TlsAcceptor::new(server_cfg);

    let client_cfg = Arc::new(
        ClientConfig::builder()
            .min_protocol_version(ProtocolVersion::Tls13)
            .max_protocol_version(ProtocolVersion::Tls13)
            .cipher_suites(&[suite])
            .with_root_certs_pem_bytes(CERT_PEM)
            .build()
            .expect("ClientConfig builds (TLS 1.3 pinned)"),
    );
    let connector = TlsConnector::new(client_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let expected = expected_iana_name.to_owned();

    let expected_server = expected.clone();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut stream = match acceptor.accept(tcp).await {
            Ok(s) => s,
            Err(Error::Ktls(KtlsError::SetSockOpt(e))) => {
                return Err(format!("server kTLS setsockopt: {e}"));
            }
            Err(e) => return Err(format!("server handshake: {e}")),
        };
        assert_eq!(stream.negotiated().version(), "TLSv1.3");
        assert_eq!(stream.negotiated().cipher(), expected_server);
        if !stream.ktls_active() {
            return Err("server kTLS did not engage".to_string());
        }
        stream
            .write_all(b"tls13 server hello")
            .await
            .expect("server write");
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.expect("server read");
        assert_eq!(&buf[..n], b"tls13 client hello");
        stream.shutdown().await.ok();
        Ok(())
    });

    let expected_client = expected;
    let client = tokio::spawn(async move {
        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut stream = match connector.connect("localhost", tcp).await {
            Ok(s) => s,
            Err(Error::Ktls(KtlsError::SetSockOpt(e))) => {
                return Err(format!("client kTLS setsockopt: {e}"));
            }
            Err(e) => return Err(format!("client handshake: {e}")),
        };
        assert_eq!(stream.negotiated().version(), "TLSv1.3");
        assert_eq!(stream.negotiated().cipher(), expected_client);
        if !stream.ktls_active() {
            return Err("client kTLS did not engage".to_string());
        }
        stream
            .write_all(b"tls13 client hello")
            .await
            .expect("client write");
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.expect("client read");
        assert_eq!(&buf[..n], b"tls13 server hello");
        stream.shutdown().await.ok();
        Ok(())
    });

    let s = server.await.unwrap();
    let c = client.await.unwrap();
    if let Err(e) = &s {
        if e.contains("setsockopt") || e.contains("did not engage") {
            println!("skipping: kernel rejected TLS 1.3 kTLS install: {e}");
            return;
        }
    }
    if let Err(e) = &c {
        if e.contains("setsockopt") || e.contains("did not engage") {
            println!("skipping: kernel rejected TLS 1.3 kTLS install: {e}");
            return;
        }
    }
    s.expect("server task ok");
    c.expect("client task ok");
}

#[tokio::test]
async fn ktls_install_tls13_aes256() {
    run_tls13_ktls_round_trip(
        tokio_aws_lc::cipher_suite::TLS13_AES_256_GCM_SHA384,
        "TLS_AES_256_GCM_SHA384",
    )
    .await;
}

#[tokio::test]
async fn ktls_install_tls13_chacha20() {
    run_tls13_ktls_round_trip(
        tokio_aws_lc::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        "TLS_CHACHA20_POLY1305_SHA256",
    )
    .await;
}

/// `disable_ktls()` on both sides must short-circuit auto-install and
/// leave the stream on the userspace AEAD path. Plaintext still
/// round-trips end-to-end.
#[tokio::test]
async fn ktls_disabled_skips_auto_install_and_round_trips_in_userspace() {
    let server_cfg = Arc::new(
        ServerConfig::builder()
            .disable_ktls()
            .with_pem_bytes(CERT_PEM, KEY_PEM)
            .expect("ServerConfig builds"),
    );
    let acceptor = TlsAcceptor::new(server_cfg);

    let client_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certs_pem_bytes(CERT_PEM)
            .disable_ktls()
            .build()
            .expect("ClientConfig builds"),
    );
    let connector = TlsConnector::new(client_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(tcp).await.expect("server handshake");
        assert!(stream.ktls_disabled(), "server stream knows it's disabled");
        assert!(!stream.ktls_active(), "auto-install must have been skipped");
        stream.write_all(b"userspace hi").await.unwrap();
        let mut buf = [0u8; 32];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"userspace bye");
        stream.shutdown().await.ok();
    });

    let client = tokio::spawn(async move {
        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut stream = connector
            .connect("localhost", tcp)
            .await
            .expect("client handshake");
        assert!(stream.ktls_disabled());
        assert!(!stream.ktls_active());
        let mut buf = [0u8; 32];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"userspace hi");
        stream.write_all(b"userspace bye").await.unwrap();
        stream.shutdown().await.ok();
    });

    server.await.unwrap();
    client.await.unwrap();
}

/// On a host where kTLS *is* available and the negotiated cipher is
/// eligible, `accept`/`connect` must auto-install kTLS without the
/// caller touching `install_ktls()`. Skips when the host doesn't
/// support kTLS.
#[tokio::test]
async fn ktls_auto_install_on_handshake_completion() {
    if !host_ktls_available() {
        println!("skipping: host_ktls_available() == false");
        return;
    }

    let server_cfg = Arc::new(
        ServerConfig::builder()
            .ktls_aead_only(true)
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
        let active = stream.ktls_active();
        // Hold the connection open until the client has had its
        // accept-side auto-install run; otherwise the test races the
        // TCP FIN against the connect-side install and we get a
        // benign `SocketUnattachable` swallow that leaves
        // `ktls_active == false`.
        stream.write_all(b"ready").await.ok();
        let mut buf = [0u8; 8];
        let _ = stream.read(&mut buf).await;
        stream.shutdown().await.ok();
        active
    });
    let client = tokio::spawn(async move {
        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut stream = connector
            .connect("localhost", tcp)
            .await
            .expect("client handshake");
        let active = stream.ktls_active();
        let mut buf = [0u8; 8];
        let _ = stream.read(&mut buf).await;
        stream.write_all(b"ack").await.ok();
        stream.shutdown().await.ok();
        active
    });
    let s_active = server.await.unwrap();
    let c_active = client.await.unwrap();
    assert!(s_active, "server side must auto-install kTLS");
    assert!(c_active, "client side must auto-install kTLS");
}
