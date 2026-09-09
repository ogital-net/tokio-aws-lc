//! Configuration regressions use loopback TCP and explicitly disable kTLS.

use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio_aws_lc::cipher_suite::{
    TLS13_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
};
use tokio_aws_lc::{
    CipherSuite, ClientConfig, ClientConfigBuilder, Error, ProtocolVersion, Result, ServerConfig,
    ServerConfigBuilder, TlsAcceptor, TlsConnector, TlsStream,
};

const CERT_DER: &[u8] = include_bytes!("data/cert.der");
const KEY_DER: &[u8] = include_bytes!("data/key.der");
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

async fn handshake(
    client: ClientConfig,
    server: ServerConfig,
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
                connector.connect("localhost", tcp).await
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
