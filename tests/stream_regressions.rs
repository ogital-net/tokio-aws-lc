//! Public-API regressions for buffering, split I/O, and TLS EOF semantics.
//! No application data is sent until *both* handshakes have completed.
//! kTLS cases skip only an unavailable host/probed kernel capability, never
//! handshake failures or unexpected userspace fallback. Set
//! `TOKIO_AWS_LC_REQUIRE_KTLS=1` to turn those explicit skips into failures.

use std::future::{poll_fn, Future};
use std::io;
use std::pin::{pin, Pin};
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::{oneshot, Barrier};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_aws_lc::cipher_suite::{
    TLS13_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
};
use tokio_aws_lc::{
    host_ktls_available, ClientConfig, ProtocolVersion, ServerConfig, TlsAcceptor, TlsConnector,
    TlsStream,
};

const CERT_DER: &[u8] = include_bytes!("data/cert.der");
const KEY_DER: &[u8] = include_bytes!("data/key.der");
const RECORD: usize = 16 * 1024;
const DEADLINE: Duration = Duration::from_secs(15);

#[derive(Clone, Copy, Debug)]
enum Offload {
    Disabled,
    ClientOnly,
    ServerOnly,
    Both,
}

impl Offload {
    fn endpoints(self) -> (bool, bool) {
        match self {
            Self::Disabled => (false, false),
            Self::ClientOnly => (true, false),
            Self::ServerOnly => (false, true),
            Self::Both => (true, true),
        }
    }
}

async fn bounded(test: impl Future<Output = ()>) {
    timeout(DEADLINE, test)
        .await
        .expect("stream regression exceeded its 15-second outer deadline");
}

async fn tcp_pair() -> (TcpStream, TcpStream) {
    // The listening socket's SO_SNDBUF is inherited by the accepted socket.
    let listener = TcpSocket::new_v4().unwrap();
    listener.set_send_buffer_size(4096).unwrap();
    listener.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let listener = listener.listen(8).unwrap();
    let socket = TcpSocket::new_v4().unwrap();
    socket.set_send_buffer_size(4096).unwrap();
    let (client, (server, _)) = tokio::try_join!(
        socket.connect(listener.local_addr().unwrap()),
        listener.accept()
    )
    .unwrap();
    client.set_nodelay(true).unwrap();
    server.set_nodelay(true).unwrap();
    (client, server)
}

async fn handshake(
    client: TcpStream,
    server: TcpStream,
    version: ProtocolVersion,
    offload: Offload,
) -> (TlsStream, TlsStream) {
    let (client_enabled, server_enabled) = offload.endpoints();
    let (suite, version_name) = match version {
        ProtocolVersion::Tls12 => (TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, "TLSv1.2"),
        ProtocolVersion::Tls13 => (TLS13_AES_128_GCM_SHA256, "TLSv1.3"),
        _ => panic!("unhandled test protocol: {version:?}"),
    };
    let mut client_config = ClientConfig::builder()
        .with_root_certs_der_bytes(&[CERT_DER])
        .min_protocol_version(version)
        .max_protocol_version(version)
        .cipher_suites(&[suite]);
    let mut server_config = ServerConfig::builder()
        .min_protocol_version(version)
        .max_protocol_version(version)
        .cipher_suites(&[suite]);
    if !client_enabled {
        client_config = client_config.disable_ktls();
    }
    if !server_enabled {
        server_config = server_config.disable_ktls();
    }
    let connector = TlsConnector::new(Arc::new(client_config.build().unwrap()));
    let acceptor = TlsAcceptor::new(Arc::new(
        server_config.with_der_bytes(&[CERT_DER], KEY_DER).unwrap(),
    ));
    // join! is also the handshake barrier: successful streams stay alive,
    // and neither endpoint can race application data against kTLS install.
    let (client, server) = tokio::join!(
        connector.connect("localhost", client),
        acceptor.accept(server)
    );
    let client = client.expect("client handshake (not a skippable failure)");
    let server = server.expect("server handshake (not a skippable failure)");
    for (name, stream, enabled) in [
        ("client", &client, client_enabled),
        ("server", &server, server_enabled),
    ] {
        assert_eq!(stream.negotiated().version(), version_name);
        assert_eq!(stream.ktls_disabled(), !enabled);
        assert_eq!(
            stream.ktls_active(),
            enabled,
            "{name}: {version:?}/{offload:?}; fallback on a probed supported host is a failure"
        );
    }
    (client, server)
}

async fn tls_pair(version: ProtocolVersion, offload: Offload) -> (TlsStream, TlsStream) {
    let (client, server) = tcp_pair().await;
    handshake(client, server, version, offload).await
}

fn pattern(len: usize, mut state: u64) -> Vec<u8> {
    // Different records/directions must not have identical repeated blocks:
    // otherwise a same-length duplicate/drop could pass byte comparisons.
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[0]
        })
        .collect()
}

fn assert_bytes(actual: &[u8], expected: &[u8]) {
    assert_eq!(actual.len(), expected.len(), "plaintext length changed");
    if let Some(offset) = actual.iter().zip(expected).position(|(a, b)| a != b) {
        panic!(
            "plaintext differs at offset {offset}: actual={} expected={}",
            actual[offset], expected[offset]
        );
    }
}

async fn write_once(stream: &mut TlsStream, bytes: &[u8]) -> Poll<io::Result<usize>> {
    let mut write = pin!(stream.write(bytes));
    // Return the inner Poll as OUTPUT, rather than awaiting readiness. On
    // Pending the write future is cancelled here, releasing its buffer.
    poll_fn(|cx| Poll::Ready(write.as_mut().poll(cx))).await
}

async fn flush_once(stream: &mut TlsStream) -> Poll<io::Result<()>> {
    poll_fn(|cx| Poll::Ready(Pin::new(&mut *stream).poll_flush(cx))).await
}

async fn shutdown_once(stream: &mut TlsStream) -> Poll<io::Result<()>> {
    poll_fn(|cx| Poll::Ready(Pin::new(&mut *stream).poll_shutdown(cx))).await
}

fn record_accepted(result: io::Result<usize>, bytes: &[u8], expected: &mut Vec<u8>) {
    let n = result.expect("write/retry must succeed, never BAD_WRITE_RETRY or BAD_LENGTH");
    assert!(
        n > 0 && n <= bytes.len().min(RECORD),
        "unbounded write: {n}"
    );
    expected.extend_from_slice(&bytes[..n]);
}

/// The peer must stay alive and unpolled throughout this helper. Its return
/// shows that an acknowledged write still needs flushing, while the latest
/// new write (including an equal-data, different-address retry) accepts
/// nothing. Only Ready(Ok(n)) contributes to the expected stream.
async fn stall_writer(stream: &mut TlsStream) -> Vec<u8> {
    let mut expected = Vec::new();
    for sequence in 1..=1024 {
        let mut bytes = pattern(3 * RECORD + 37, sequence);
        match write_once(stream, &bytes).await {
            Poll::Ready(result) => {
                record_accepted(result, &bytes, &mut expected);
                // An SSL WANT must have copied its accepted plaintext. Do
                // not leave the caller's original storage unchanged/alive.
                bytes.fill(0xee);
            }
            Poll::Pending => {
                // This buffer has NEVER been accepted. In particular, do
                // not retry a buffer from a successful write, which would
                // legitimately ask AsyncWrite to send it a second time.
                let mut moved = bytes.clone();
                assert_eq!(moved, bytes);
                assert_ne!(moved.as_ptr(), bytes.as_ptr());
                bytes.fill(0xdd);
                drop(bytes);
                match write_once(stream, &moved).await {
                    Poll::Ready(result) => {
                        // Kernel ACKs can free capacity even though the
                        // application is paused. Account for this success
                        // and refill instead of making a timing assumption.
                        record_accepted(result, &moved, &mut expected);
                        moved.fill(0xcc);
                    }
                    Poll::Pending => match flush_once(stream).await {
                        Poll::Pending => {
                            assert_ne!(expected, [] as [u8; 0]);
                            moved.fill(0xbb);
                            return expected;
                        }
                        Poll::Ready(result) => result.expect("flush after cancelled write"),
                    },
                }
            }
        }
        // Keep the outer deadline cooperative without ever polling the peer.
        tokio::task::yield_now().await;
    }
    panic!("paused peer never produced a pending write AND pending flush");
}

async fn assert_shutdown_idempotent(stream: &mut TlsStream) {
    for _ in 0..3 {
        match shutdown_once(stream).await {
            Poll::Ready(result) => result.expect("repeated shutdown"),
            Poll::Pending => panic!("completed shutdown must be immediately idempotent"),
        }
    }
    let error = stream.write(b"write after shutdown").await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    stream
        .flush()
        .await
        .expect("flush after completed shutdown");
}

async fn cancelled_write(version: ProtocolVersion) {
    let (mut client, mut server) = tls_pair(version, Offload::Disabled).await;
    let mut expected = stall_writer(&mut client).await;
    let replacement = b"a different, short message after cancelling the blocked new write";
    expected.extend_from_slice(replacement);
    let send = async {
        client
            .write_all(replacement)
            .await
            .expect("different-length write after cancellation, not BAD_WRITE_RETRY");
        client.flush().await.expect("flush replacement");
        client.shutdown().await.expect("final shutdown");
    };
    let receive = async {
        let mut actual = Vec::new();
        server.read_to_end(&mut actual).await.expect("clean EOF");
        assert_bytes(&actual, &expected);
    };
    tokio::join!(send, receive);
}

async fn flush_drains(version: ProtocolVersion) {
    let (mut client, mut server) = tls_pair(version, Offload::Disabled).await;
    let expected = stall_writer(&mut client).await;
    let (read_tx, read_rx) = oneshot::channel();
    let send = async {
        client
            .flush()
            .await
            .expect("flush accepted pending plaintext");
        // Neither a later write nor shutdown may rescue a no-op flush.
        read_rx
            .await
            .expect("peer read everything using flush alone");
        client.shutdown().await.expect("shutdown after flush");
    };
    let receive = async {
        let mut actual = vec![0; expected.len()];
        server.read_exact(&mut actual).await.expect("flushed bytes");
        assert_bytes(&actual, &expected);
        read_tx.send(()).unwrap();
        let mut tail = Vec::new();
        server.read_to_end(&mut tail).await.expect("clean EOF");
        assert!(tail.is_empty(), "cancelled or duplicated plaintext leaked");
    };
    tokio::join!(send, receive);
}

async fn shutdown_drains(version: ProtocolVersion) {
    let (mut client, mut server) = tls_pair(version, Offload::Disabled).await;
    let expected = stall_writer(&mut client).await;
    // Exercise cancellation of a pending shutdown too. Kernel ACKs may
    // have freed capacity since the observed pending flush, so successful
    // immediate completion is also legal; losing accepted bytes is not.
    if let Poll::Ready(result) = shutdown_once(&mut client).await {
        result.expect("first shutdown poll must flush before completing");
    }
    let send = async {
        // No explicit flush: shutdown itself must drain the accepted chunk.
        client
            .shutdown()
            .await
            .expect("shutdown flushes queued bytes");
        assert_shutdown_idempotent(&mut client).await;
    };
    let receive = async {
        let mut actual = Vec::new();
        server.read_to_end(&mut actual).await.expect("clean EOF");
        assert_bytes(&actual, &expected);
    };
    tokio::join!(send, receive);
}

async fn split_full_duplex(version: ProtocolVersion) {
    let (mut client, mut server) = tls_pair(version, Offload::Disabled).await;
    // Start BOTH directions with accepted output blocked on the other
    // side. A read implementation that waits for its own flush deadlocks.
    let mut client_expected = stall_writer(&mut client).await;
    let mut server_expected = stall_writer(&mut server).await;
    let client_tail = pattern(3 * 1024 * 1024 + 113, 0x1234_5678);
    let server_tail = pattern(3 * 1024 * 1024 + 279, 0x9876_5432);
    client_expected.extend_from_slice(&client_tail);
    server_expected.extend_from_slice(&server_tail);

    let start = Arc::new(Barrier::new(4));
    // Separate tasks are important: join! on four futures in one task
    // would give them the same waker and could conceal lost-waker bugs.
    // JoinSet aborts every child if the outer deadline cancels this test.
    let mut tasks = JoinSet::new();
    for (stream, outgoing, expected) in [
        (client, client_tail, server_expected),
        (server, server_tail, client_expected),
    ] {
        let (mut reader, mut writer) = tokio::io::split(stream);
        let write_start = Arc::clone(&start);
        tasks.spawn(async move {
            write_start.wait().await;
            writer.write_all(&outgoing).await.expect("split writer");
            writer.shutdown().await.expect("split shutdown flush");
        });
        let read_start = Arc::clone(&start);
        tasks.spawn(async move {
            read_start.wait().await;
            let mut actual = Vec::new();
            reader.read_to_end(&mut actual).await.expect("split reader");
            assert_bytes(&actual, &expected);
        });
    }
    while let Some(result) = tasks.join_next().await {
        result.expect("full-duplex task panicked");
    }
}

fn observe_transport(stream: TcpStream) -> (TcpStream, TcpStream) {
    let stream = stream.into_std().unwrap();
    let observer = stream.try_clone().unwrap();
    (
        TcpStream::from_std(stream).unwrap(),
        TcpStream::from_std(observer).unwrap(),
    )
}

async fn assert_no_extra_records(observer: &TcpStream) {
    let mut byte = [0; 1];
    // The TLS reader already consumed the first close_notify BEFORE the
    // repeated shutdowns. Peek below libssl: its sticky EOF could otherwise
    // hide duplicate alerts. kTLS may already have half-closed TCP (Ok(0));
    // userspace may keep TCP open, in which case no readability is expected.
    match timeout(Duration::from_millis(100), observer.peek(&mut byte)).await {
        Err(_) | Ok(Ok(0)) => {}
        other => panic!("extra record/error after repeated shutdown: {other:?}"),
    }
}

async fn read_clean(stream: &mut TlsStream, one_byte: bool) -> Vec<u8> {
    let mut actual = Vec::new();
    if one_byte {
        let mut byte = [0; 1];
        while stream.read(&mut byte).await.expect("one-byte TLS read") != 0 {
            actual.push(byte[0]);
        }
    } else {
        stream
            .read_to_end(&mut actual)
            .await
            .expect("graceful read_to_end");
    }
    for _ in 0..3 {
        assert_eq!(stream.read(&mut [0; 1]).await.expect("sticky clean EOF"), 0);
    }
    actual
}

async fn graceful(version: ProtocolVersion, offload: Offload, client_one_byte: bool) {
    let (client_tcp, server_tcp) = tcp_pair().await;
    let (client_tcp, client_observer) = observe_transport(client_tcp);
    let (server_tcp, server_observer) = observe_transport(server_tcp);
    let (mut client, mut server) = handshake(client_tcp, server_tcp, version, offload).await;
    let client_data = pattern(257, 0x1234);
    let server_data = pattern(383, 0xabcd);
    // Both sides write before reading a close alert, including for TLS 1.2.
    tokio::join!(
        async {
            client.write_all(&client_data).await.expect("client data");
            client.shutdown().await.expect("client close_notify");
        },
        async {
            server.write_all(&server_data).await.expect("server data");
            server.shutdown().await.expect("server close_notify");
        }
    );
    let (client_read, server_read) = tokio::join!(
        read_clean(&mut client, client_one_byte),
        read_clean(&mut server, !client_one_byte)
    );
    assert_bytes(&client_read, &server_data);
    assert_bytes(&server_read, &client_data);
    // The one-byte reader must handle a TWO-byte TLS alert independently
    // of application-buffer capacity, without leaking either alert byte.
    tokio::join!(
        assert_shutdown_idempotent(&mut client),
        assert_shutdown_idempotent(&mut server)
    );
    tokio::join!(
        assert_no_extra_records(&client_observer),
        assert_no_extra_records(&server_observer)
    );
}

async fn bare_drop(version: ProtocolVersion, offload: Offload, drop_client: bool) {
    let (client, server) = tls_pair(version, offload).await;
    let (mut sender, mut receiver) = if drop_client {
        (client, server)
    } else {
        (server, client)
    };
    let data = b"read all of this before dropping the peer without close_notify";
    let (read_tx, read_rx) = oneshot::channel();
    let send = async move {
        sender.write_all(data).await.expect("data before bare drop");
        sender.flush().await.expect("flush before bare drop");
        // No unread application data, no linger/RST, and no timing sleep:
        // the receiver explicitly acknowledges consuming the final bytes.
        read_rx.await.expect("receiver acknowledged final data");
        drop(sender);
    };
    let receive = async move {
        let mut actual = vec![0; data.len()];
        receiver.read_exact(&mut actual).await.expect("final data");
        assert_bytes(&actual, data);
        read_tx.send(()).unwrap();
        let mut tail = Vec::new();
        let error = receiver.read_to_end(&mut tail).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(tail, [] as [u8; 0]);
        for _ in 0..3 {
            let error = receiver.read(&mut [0; 1]).await.unwrap_err();
            assert_eq!(
                error.kind(),
                io::ErrorKind::UnexpectedEof,
                "EOF must be sticky"
            );
        }
    };
    tokio::join!(send, receive);
}

fn skip_ktls(reason: impl std::fmt::Display) -> bool {
    assert!(
        !matches!(
            std::env::var("TOKIO_AWS_LC_REQUIRE_KTLS").as_deref(),
            Ok("1")
        ),
        "TOKIO_AWS_LC_REQUIRE_KTLS=1 forbids skipping: {reason}"
    );
    eprintln!("SKIP kTLS stream regression: {reason}");
    false
}

// `async` is required so the call site's `.await` works uniformly across
// platforms; only the Linux branch actually awaits anything.
#[cfg_attr(not(target_os = "linux"), allow(clippy::unused_async))]
async fn ktls_supported(version: ProtocolVersion) -> bool {
    if !host_ktls_available() {
        return skip_ktls("host kTLS is unavailable/not supported");
    }
    #[cfg(target_os = "linux")]
    {
        kernel_probe::supported(version).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = version;
        skip_ktls("kTLS is unsupported on this platform")
    }
}

#[cfg(target_os = "linux")]
mod kernel_probe {
    use std::os::fd::AsRawFd;

    use super::{io, skip_ktls, tcp_pair, ProtocolVersion, TcpStream};

    // Linux UAPI <linux/tls.h>, deliberately independent of crate-private
    // crypto-info/stream fields. This probe uses dummy keys on a disposable
    // TCP connection and sends no data. It distinguishes an old kernel
    // without TLS 1.3 support from a broken auto-install implementation.
    #[repr(C)]
    struct Aes128Gcm {
        version: u16,
        cipher_type: u16,
        iv: [u8; 8],
        key: [u8; 16],
        salt: [u8; 4],
        rec_seq: [u8; 8],
    }

    fn option<T>(stream: &TcpStream, level: i32, name: i32, value: &T) -> io::Result<()> {
        // SAFETY: live connected fd; value is initialized and readable for
        // its complete size. setsockopt copies it before returning.
        let result = unsafe {
            libc::setsockopt(
                stream.as_raw_fd(),
                level,
                name,
                std::ptr::from_ref(value).cast(),
                libc::socklen_t::try_from(std::mem::size_of::<T>()).unwrap(),
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub(super) async fn supported(version: ProtocolVersion) -> bool {
        let (socket, _peer) = tcp_pair().await;
        if let Err(error) = option(&socket, libc::SOL_TCP, libc::TCP_ULP, b"tls\0") {
            return match error.raw_os_error() {
                Some(libc::ENOENT | libc::ENOPROTOOPT | libc::EOPNOTSUPP) => {
                    skip_ktls(format!("kernel TLS ULP unavailable: {error}"))
                }
                _ => panic!("unexpected kernel TLS ULP probe failure: {error}"),
            };
        }
        let info = Aes128Gcm {
            version: match version {
                ProtocolVersion::Tls12 => 0x0303,
                ProtocolVersion::Tls13 => 0x0304,
                _ => panic!("unhandled test protocol: {version:?}"),
            },
            cipher_type: 51, // TLS_CIPHER_AES_GCM_128
            iv: [0; 8],
            key: [0; 16],
            salt: [0; 4],
            rec_seq: [0; 8],
        };
        assert_eq!(std::mem::size_of_val(&info), 40);
        for direction in [2, 1] {
            // SOL_TLS = 282, TLS_RX = 2, TLS_TX = 1.
            if let Err(error) = option(&socket, 282, direction, &info) {
                return match error.raw_os_error() {
                    Some(libc::EINVAL | libc::ENOENT | libc::ENOPROTOOPT | libc::EOPNOTSUPP) => {
                        skip_ktls(format!(
                            "kernel {version:?}/AES-128-GCM unsupported: {error}"
                        ))
                    }
                    _ => panic!("unexpected kernel crypto capability probe failure: {error}"),
                };
            }
        }
        true
    }
}

macro_rules! userspace_case {
    ($name:ident, $version:ident, $body:ident) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn $name() {
            bounded($body(ProtocolVersion::$version)).await;
        }
    };
}

userspace_case!(userspace_tls12_cancelled_write, Tls12, cancelled_write);
userspace_case!(userspace_tls13_cancelled_write, Tls13, cancelled_write);
userspace_case!(userspace_tls12_flush_drains, Tls12, flush_drains);
userspace_case!(userspace_tls13_flush_drains, Tls13, flush_drains);
userspace_case!(userspace_tls12_shutdown_drains, Tls12, shutdown_drains);
userspace_case!(userspace_tls13_shutdown_drains, Tls13, shutdown_drains);
userspace_case!(userspace_tls12_split_full_duplex, Tls12, split_full_duplex);
userspace_case!(userspace_tls13_split_full_duplex, Tls13, split_full_duplex);

macro_rules! lifecycle_case {
    ($name:ident, $version:ident, $offload:ident) => {
        #[tokio::test]
        async fn $name() {
            bounded(async {
                let version = ProtocolVersion::$version;
                let offload = Offload::$offload;
                if !matches!(offload, Offload::Disabled) && !ktls_supported(version).await {
                    return;
                }
                for client_one_byte in [false, true] {
                    graceful(version, offload, client_one_byte).await;
                    bare_drop(version, offload, client_one_byte).await;
                }
            })
            .await;
        }
    };
}

lifecycle_case!(userspace_tls12_lifecycle, Tls12, Disabled);
lifecycle_case!(userspace_tls13_lifecycle, Tls13, Disabled);
lifecycle_case!(ktls_tls12_client_enabled_server_disabled, Tls12, ClientOnly);
lifecycle_case!(ktls_tls12_client_disabled_server_enabled, Tls12, ServerOnly);
lifecycle_case!(ktls_tls12_both_enabled, Tls12, Both);
lifecycle_case!(ktls_tls13_client_enabled_server_disabled, Tls13, ClientOnly);
lifecycle_case!(ktls_tls13_client_disabled_server_enabled, Tls13, ServerOnly);
lifecycle_case!(ktls_tls13_both_enabled, Tls13, Both);
