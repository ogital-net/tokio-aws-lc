//! `TlsStream`: the AsyncRead+AsyncWrite side of an established TLS
//! session. Drives `SSL_read`/`SSL_write` against the underlying
//! [`tokio::net::TcpStream`].
//!
//! The fd lives inside the [`tokio::net::TcpStream`]; the `SSL` is
//! given a `BIO_new_socket(fd, BIO_NOCLOSE)` so it never closes the
//! underlying socket on drop. The crate-internal handshake driver lives
//! here too so both server and client paths can share it.

use std::io;
use std::os::fd::AsRawFd as _;
use std::os::raw::c_int;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{ready, Context, Poll, Wake, Waker};

use tokio::io::{AsyncRead, AsyncWrite, Interest, ReadBuf};
use tokio::net::TcpStream;

use crate::error::{last_error, Error, KtlsError, Result};
use crate::ffi::Ssl;
use crate::session::{export_keying_material, KtlsEligibility, NegotiatedSession};

const MAX_PLAINTEXT: usize = 16 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Shutdown {
    Open,
    Sending,
    Closed,
}

// SSL reads can need write readiness and vice versa. Tokio keeps only
// one waker per socket direction, so split halves must share a wakeup.
// Allocated lazily; successful I/O never locks or creates a waker.
#[derive(Default)]
struct IoWaiters(Mutex<[Option<Waker>; 2]>);

impl IoWaiters {
    fn register(&self, reader: bool, waker: &Waker) {
        let mut slots = self.0.lock().expect("I/O waker lock poisoned");
        let slot = &mut slots[usize::from(reader)];
        if !slot.as_ref().is_some_and(|old| old.will_wake(waker)) {
            *slot = Some(waker.clone());
        }
    }

    fn notify(&self) {
        let slots = std::mem::take(&mut *self.0.lock().expect("I/O waker lock poisoned"));
        for waker in slots.into_iter().flatten() {
            waker.wake();
        }
    }
}

impl Wake for IoWaiters {
    fn wake(self: Arc<Self>) {
        self.notify();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.notify();
    }
}

/// Established TLS session.
///
/// Created by [`crate::TlsAcceptor::accept`] (server) or
/// [`crate::TlsConnector::connect`] (client). Implements `AsyncRead` +
/// `AsyncWrite`; errors surface as plain [`io::Error`] so framed codecs
/// and `tokio::io::copy` work without conversion.
///
/// Userspace writes normally go directly to AWS-LC. Under backpressure,
/// at most one 16 KiB plaintext chunk is buffered and reported as accepted.
/// Call `flush()` or `shutdown()` to finish sending it. A write returning
/// `Pending` has not accepted any bytes from that call's buffer.
pub struct TlsStream {
    // Field order matters for Drop: `ssl` first (frees the SSL, which
    // drops one refcount on the SSL_CTX — the CTX-owned ALPN buffer
    // and any other ex_data are released when the last refcount goes,
    // typically when the producing config is also dropped); then `tcp`
    // closes the socket. The SSL's BIO uses BIO_NOCLOSE so the SSL
    // never touches the fd.
    ssl: Ssl,
    tcp: TcpStream,
    /// `true` once kTLS has been installed: the read/write path then
    /// bypasses libssl and goes straight to `read(2)` / `write(2)` on
    /// the fd (the kernel `tls` ULP handles the record layer).
    ktls_active: bool,
    /// Mirrors the producing config's `disable_ktls()` setting.
    /// When `true`, automatic post-handshake install is skipped and
    /// the stream stays on the userspace AEAD path.
    ktls_disabled: bool,
    /// Empty on the fast path. Capacity is reused after the first stall.
    pending_write: Vec<u8>,
    waiters: Option<Arc<IoWaiters>>,
    write_error: Option<io::Error>,
    shutdown: Shutdown,
    #[cfg(target_os = "linux")]
    ktls_reader: crate::ktls::io::RecordReader,
}

impl std::fmt::Debug for TlsStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsStream")
            .field("fd", &self.tcp.as_raw_fd())
            .field("ktls_active", &self.ktls_active)
            .finish_non_exhaustive()
    }
}

// SAFETY: TlsStream can be moved between threads. The SSL is single-
// threaded, mirrored from the ffi::Ssl wrapper. tokio::net::TcpStream
// is Send. We deliberately do not implement Sync.
unsafe impl Send for TlsStream {}

impl TlsStream {
    pub(crate) fn from_parts(ssl: Ssl, tcp: TcpStream, ktls_disabled: bool) -> Self {
        // SAFETY: exclusive, live SSL. A blocked write is copied into
        // owned storage before returning; retries preserve bytes/length,
        // but not the original caller's address. One record per call
        // bounds both unreported writes and our slow-path allocation.
        unsafe {
            aws_lc_sys::SSL_set_mode(
                ssl.as_ptr(),
                u32::try_from(aws_lc_sys::SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER)
                    .expect("SSL mode fits in u32"),
            );
        }
        Self {
            ssl,
            tcp,
            ktls_active: false,
            ktls_disabled,
            pending_write: Vec::new(),
            waiters: None,
            write_error: None,
            shutdown: Shutdown::Open,
            #[cfg(target_os = "linux")]
            ktls_reader: crate::ktls::io::RecordReader::default(),
        }
    }

    fn poll_ssl_ready(
        &mut self,
        code: c_int,
        cx: &Context<'_>,
        reader: bool,
    ) -> Poll<io::Result<()>> {
        let waiters = self
            .waiters
            .get_or_insert_with(|| Arc::new(IoWaiters::default()));
        waiters.register(reader, cx.waker());
        let waker = Waker::from(Arc::clone(waiters));
        let mut shared = Context::from_waker(&waker);
        if code == aws_lc_sys::SSL_ERROR_WANT_READ {
            poll_clear_read_ready(&self.tcp, &mut shared)
        } else {
            poll_clear_write_ready(&self.tcp, &mut shared)
        }
    }

    fn write_failure(&mut self, error: io::Error) -> io::Error {
        self.write_error = Some(duplicate_io_error(&error));
        if let Some(waiters) = &self.waiters {
            waiters.notify();
        }
        error
    }

    fn poll_pending_write(&mut self, cx: &Context<'_>, reader: bool) -> Poll<io::Result<()>> {
        if let Some(error) = &self.write_error {
            return Poll::Ready(Err(duplicate_io_error(error)));
        }
        while !self.pending_write.is_empty() {
            let len = c_int::try_from(self.pending_write.len()).expect("one TLS record");
            // SAFETY: pending_write owns the identical plaintext of the
            // blocked call. AWS-LC permits its new address via the mode
            // set in from_parts. Partial-write mode is not enabled.
            let n = unsafe {
                aws_lc_sys::SSL_write(self.ssl.as_ptr(), self.pending_write.as_ptr().cast(), len)
            };
            if n == len {
                self.pending_write.clear();
                if let Some(waiters) = &self.waiters {
                    waiters.notify();
                }
                break;
            }
            // SAFETY: immediately follows this SSL's failed operation.
            let code = unsafe { aws_lc_sys::SSL_get_error(self.ssl.as_ptr(), n) };
            if matches!(
                code,
                aws_lc_sys::SSL_ERROR_WANT_READ | aws_lc_sys::SSL_ERROR_WANT_WRITE
            ) {
                if let Err(error) = ready!(self.poll_ssl_ready(code, cx, reader)) {
                    return Poll::Ready(Err(self.write_failure(error)));
                }
            } else {
                let error = ssl_io_error("SSL_write", code);
                return Poll::Ready(Err(self.write_failure(error)));
            }
        }
        Poll::Ready(Ok(()))
    }

    /// Snapshot of the negotiated session: version, cipher, ALPN, SNI.
    #[must_use]
    pub fn negotiated(&self) -> NegotiatedSession {
        // SAFETY: ssl is live and post-handshake (TlsStream is only handed
        // out after the handshake completes).
        unsafe { NegotiatedSession::from_ssl(self.ssl.as_ptr()) }
    }

    /// Whether the current session is structurally eligible for Linux
    /// kTLS offload. Does *not* check the host kernel; auto-install
    /// runs on handshake completion. Rejections before either direction
    /// is active fall back to userspace; partial installs fail closed. Observe
    /// [`Self::ktls_active`] to confirm whether the kernel actually
    /// took over the data path.
    #[must_use]
    pub fn ktls_eligibility(&self) -> KtlsEligibility {
        // SAFETY: ssl is live and post-handshake.
        unsafe { KtlsEligibility::from_ssl(&self.ssl) }
    }

    /// Whether the kernel `tls` ULP has been installed for this stream.
    /// `true` after the handshake completes if the negotiated session
    /// is kTLS-eligible and the host kernel accepted the install.
    #[must_use]
    pub fn ktls_active(&self) -> bool {
        self.ktls_active
    }

    /// Whether kTLS is disabled on this stream's config (via
    /// [`crate::ServerConfigBuilder::disable_ktls`] /
    /// [`crate::ClientConfigBuilder::disable_ktls`]). When `true`,
    /// automatic post-handshake install is skipped and the stream
    /// stays on the userspace AEAD path.
    #[must_use]
    pub fn ktls_disabled(&self) -> bool {
        self.ktls_disabled
    }

    /// Post-handshake auto-install entry point. Called by the
    /// acceptor/connector after the handshake completes, unless the
    /// producing config opted out via `disable_ktls()`. Swallows the
    /// failure modes that indicate kTLS is structurally unavailable on
    /// this host / for this negotiation (`Unsupported`,
    /// `IneligibleCipher`, `TlsUlpUnavailable`, `SocketUnattachable`,
    /// `CryptoUnavailable`)
    /// so the stream silently continues on the userspace path.
    /// RX is installed first. Its rejection leaves both directions on
    /// TCP; a subsequent TX failure leaves RX active and is fatal.
    ///
    /// On Linux the kernel `tls` module must be loaded
    /// (`sudo modprobe tls`, or add `tls` to `/etc/modules-load.d/`)
    /// for kTLS to engage. Container workloads need the *host* kernel
    /// to provide it. Call [`crate::host_ktls_available`] at startup
    /// to branch on host support, or check [`Self::ktls_active`]
    /// post-handshake to see whether the install actually happened.
    ///
    /// # Post-handshake records
    ///
    /// `recvmsg` distinguishes application data from authenticated
    /// `close_notify` alerts. A bare TCP FIN is `UnexpectedEof`.
    /// Handshake controls, including TLS 1.3 `NewSessionTicket` and
    /// `KeyUpdate`, remain unsupported and produce a terminal error.
    /// Disable kTLS when these are needed; libssl then processes them.
    ///
    /// Server-emitted post-handshake records cannot happen on this
    /// crate's server path: tickets are disabled by construction
    /// (`SSL_OP_NO_TICKET` + `SSL_CTX_set_num_tickets(0)`), and we do
    /// not call `SSL_key_update` ourselves.
    pub(crate) fn try_auto_install_ktls(&mut self) -> Result<()> {
        if self.ktls_active || self.ktls_disabled {
            return Ok(());
        }
        // Buffered (decrypted or undecrypted) data at install time is a
        // transient, timing-dependent condition — not a structural
        // "kTLS unavailable" one — so treat it like the other non-fatal
        // cases below: skip the install and let the connection proceed
        // on the userspace AEAD path, where libssl reads the buffered
        // bytes correctly. Failing the whole connection here would drop
        // clients whose first record merely coalesced with the
        // handshake's final TCP segment.
        if let Err(e) = crate::ktls::check_no_buffered_plaintext(&self.ssl) {
            match e {
                Error::Ktls(KtlsError::BufferedPlaintext(_)) => return Ok(()),
                other => return Err(other),
            }
        }
        let raw = self.tcp.as_raw_fd();
        match crate::ktls::install_ktls(&self.ssl, raw) {
            Ok(()) => {
                self.ktls_active = true;
                Ok(())
            }
            Err(Error::Ktls(
                KtlsError::Unsupported
                | KtlsError::IneligibleCipher { .. }
                | KtlsError::TlsUlpUnavailable(_)
                | KtlsError::SocketUnattachable(_)
                | KtlsError::CryptoUnavailable(_),
            )) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// RFC 5705 keying-material exporter.
    pub fn export_keying_material(
        &self,
        out: &mut [u8],
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Result<()> {
        // SAFETY: ssl is live and post-handshake.
        unsafe { export_keying_material(self.ssl.as_ptr(), out, label, context) }
    }

    /// Whether the peer presented a certificate during the handshake.
    /// Always true on the client side (server certs are mandatory); on
    /// the server side this depends on the [`crate::ClientAuthMode`].
    #[must_use]
    pub fn has_peer_certificate(&self) -> bool {
        // SAFETY: ssl is live and post-handshake. SSL_get_peer_certificate
        // returns an owned X509* (refcount bumped) or null. We free it
        // immediately since we only care about presence here.
        let cert = unsafe { aws_lc_sys::SSL_get_peer_certificate(self.ssl.as_ptr()) };
        if cert.is_null() {
            false
        } else {
            // SAFETY: we own the refcount returned by SSL_get_peer_certificate.
            unsafe {
                aws_lc_sys::X509_free(cert);
            }
            true
        }
    }
}

impl AsyncRead for TlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        #[cfg(target_os = "linux")]
        if this.ktls_active {
            return this.ktls_reader.poll_read(&this.tcp, cx, buf);
        }
        // Flush accepted output when switching to reading (e.g. a
        // request/response exchange), but do not block inbound progress
        // on outbound backpressure: split peers may both be writing.
        if let Poll::Ready(Err(error)) = this.poll_pending_write(cx, true) {
            return Poll::Ready(Err(error));
        }
        loop {
            let unfilled = buf.initialize_unfilled();
            if unfilled.is_empty() {
                return Poll::Ready(Ok(()));
            }
            #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
            let cap = unfilled.len().min(c_int::MAX as usize) as c_int;
            // SAFETY: ssl is live; unfilled is a writable buffer of
            // length `cap` bytes.
            let n = unsafe {
                aws_lc_sys::SSL_read(this.ssl.as_ptr(), unfilled.as_mut_ptr().cast(), cap)
            };
            if n > 0 {
                #[allow(clippy::cast_sign_loss)]
                buf.advance(n as usize);
                return Poll::Ready(Ok(()));
            }
            // SAFETY: ssl is live; SSL_get_error inspects the last
            // operation's outcome.
            let err = unsafe { aws_lc_sys::SSL_get_error(this.ssl.as_ptr(), n) };
            match err {
                aws_lc_sys::SSL_ERROR_ZERO_RETURN => return Poll::Ready(Ok(())),
                aws_lc_sys::SSL_ERROR_WANT_READ | aws_lc_sys::SSL_ERROR_WANT_WRITE => {
                    ready!(this.poll_ssl_ready(err, cx, true))?;
                }
                _ => return Poll::Ready(Err(ssl_io_error("SSL_read", err))),
            }
        }
    }
}

impl AsyncWrite for TlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if let Some(error) = &this.write_error {
            return Poll::Ready(Err(duplicate_io_error(error)));
        }
        if this.shutdown != Shutdown::Open {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TLS write half is shut down",
            )));
        }
        if this.ktls_active {
            return ktls_poll_write(&this.tcp, cx, buf);
        }
        ready!(this.poll_pending_write(cx, false))?;
        let chunk = &buf[..buf.len().min(MAX_PLAINTEXT)];
        let len = c_int::try_from(chunk.len()).expect("one TLS record");
        // SAFETY: live SSL; chunk remains readable through this call.
        let n = unsafe { aws_lc_sys::SSL_write(this.ssl.as_ptr(), chunk.as_ptr().cast(), len) };
        if n > 0 {
            return Poll::Ready(Ok(usize::try_from(n).expect("positive write")));
        }
        // SAFETY: immediately follows the failed SSL_write.
        let code = unsafe { aws_lc_sys::SSL_get_error(this.ssl.as_ptr(), n) };
        if matches!(
            code,
            aws_lc_sys::SSL_ERROR_WANT_READ | aws_lc_sys::SSL_ERROR_WANT_WRITE
        ) {
            // SSL has committed to this plaintext. Own it and ACK it
            // now, never return Pending after accepting caller bytes.
            this.pending_write.extend_from_slice(chunk);
            Poll::Ready(Ok(chunk.len()))
        } else {
            let error = ssl_io_error("SSL_write", code);
            Poll::Ready(Err(this.write_failure(error)))
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_pending_write(cx, false)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(this.poll_pending_write(cx, false))?;
        if this.shutdown == Shutdown::Closed {
            return Poll::Ready(Ok(()));
        }
        this.shutdown = Shutdown::Sending;
        #[cfg(target_os = "linux")]
        if this.ktls_active {
            if let Err(error) = ready!(crate::ktls::io::poll_close_notify(&this.tcp, cx)) {
                return Poll::Ready(Err(this.write_failure(error)));
            }
            // close_notify has been accepted exactly once. Tokio's TCP
            // shutdown is a synchronous shutdown(SHUT_WR), not a flush.
            this.shutdown = Shutdown::Closed;
            let result = ready!(Pin::new(&mut this.tcp).poll_shutdown(cx));
            return Poll::Ready(result.map_err(|error| this.write_failure(error)));
        }
        loop {
            // SAFETY: ssl is live.
            let r = unsafe { aws_lc_sys::SSL_shutdown(this.ssl.as_ptr()) };
            if r >= 0 {
                // 0 = our close_notify sent; 1 = peer's also seen.
                // Either is "done" from our side.
                this.shutdown = Shutdown::Closed;
                return Poll::Ready(Ok(()));
            }
            // SAFETY: ssl is live.
            let err = unsafe { aws_lc_sys::SSL_get_error(this.ssl.as_ptr(), r) };
            match err {
                aws_lc_sys::SSL_ERROR_WANT_READ | aws_lc_sys::SSL_ERROR_WANT_WRITE => {
                    if let Err(error) = ready!(this.poll_ssl_ready(err, cx, false)) {
                        return Poll::Ready(Err(this.write_failure(error)));
                    }
                }
                _ => {
                    let error = ssl_io_error("SSL_shutdown", err);
                    return Poll::Ready(Err(this.write_failure(error)));
                }
            }
        }
    }
}

/// kTLS-mode `poll_write`: `write(2)` plaintext directly to the socket.
fn ktls_poll_write(tcp: &TcpStream, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
    loop {
        match tcp.try_write(buf) {
            Ok(n) => return Poll::Ready(Ok(n)),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => match tcp.poll_write_ready(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            },
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Poll::Ready(Err(e)),
        }
    }
}

/// Wait for read readiness, then force-clear the cached bit. libssl's
/// BIO does the actual `recv(2)` outside tokio's bookkeeping, so we
/// have to invalidate the cache after each `WANT_READ` ourselves —
/// otherwise `poll_read_ready` would keep returning `Ready` from the
/// stale notification and busy-loop. The `try_io(_, || Err(WouldBlock))`
/// idiom is tokio's documented escape hatch for this.
fn poll_clear_read_ready(tcp: &TcpStream, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    match tcp.poll_read_ready(cx) {
        Poll::Ready(Ok(())) => {
            let _: io::Result<()> =
                tcp.try_io(Interest::READABLE, || Err(io::ErrorKind::WouldBlock.into()));
            Poll::Ready(Ok(()))
        }
        other => other,
    }
}

/// Mirror of [`poll_clear_read_ready`] for the write half.
fn poll_clear_write_ready(tcp: &TcpStream, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    match tcp.poll_write_ready(cx) {
        Poll::Ready(Ok(())) => {
            let _: io::Result<()> =
                tcp.try_io(Interest::WRITABLE, || Err(io::ErrorKind::WouldBlock.into()));
            Poll::Ready(Ok(()))
        }
        other => other,
    }
}

/// Build an `io::Error` from the last AWS-LC failure on the current
/// thread, prefixed with which call surfaced it.
fn ssl_io_error(op: &'static str, code: c_int) -> io::Error {
    let os_error = io::Error::last_os_error();
    let detail = last_error();
    if code == aws_lc_sys::SSL_ERROR_SYSCALL {
        if os_error.raw_os_error().is_some_and(|errno| errno != 0) {
            return os_error;
        }
        return io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "TLS peer closed without close_notify",
        );
    }
    io::Error::other(format!("{op}: ssl_error={code} {detail}"))
}

fn duplicate_io_error(error: &io::Error) -> io::Error {
    error.raw_os_error().map_or_else(
        || io::Error::new(error.kind(), error.to_string()),
        io::Error::from_raw_os_error,
    )
}

/// Attach a BIO that does *not* close the fd on free; the
/// [`TcpStream`] retains sole ownership of socket lifetime.
///
/// # Safety
///
/// `ssl` must be a live `SSL` handle that has not yet had a BIO
/// installed. `fd` must be a non-blocking socket valid for the lifetime
/// of the SSL handle.
pub(crate) unsafe fn attach_socket_bio(ssl: &mut Ssl, fd: c_int) -> Result<()> {
    // SAFETY: BIO_new_socket allocates and returns an owned BIO over the
    // given fd; BIO_NOCLOSE leaves close-on-free disabled.
    let bio = unsafe { aws_lc_sys::BIO_new_socket(fd, aws_lc_sys::BIO_NOCLOSE) };
    if bio.is_null() {
        return Err(Error::Init(format!("BIO_new_socket: {}", last_error())));
    }
    // SAFETY: ssl is live; SSL_set_bio takes ownership of the BIO (one
    // reference, since rbio == wbio).
    unsafe {
        aws_lc_sys::SSL_set_bio(ssl.as_ptr(), bio, bio);
    }
    Ok(())
}

/// Drive `SSL_do_handshake` to completion against a [`TcpStream`].
///
/// # Safety
///
/// `ssl` must be a live SSL handle wired to `tcp`'s fd via
/// [`attach_socket_bio`] and pre-set with `SSL_set_accept_state` or
/// `SSL_set_connect_state`.
pub(crate) async unsafe fn drive_handshake(ssl: &mut Ssl, tcp: &TcpStream) -> Result<()> {
    loop {
        // SAFETY: ssl is live per caller contract.
        let r = unsafe { aws_lc_sys::SSL_do_handshake(ssl.as_ptr()) };
        if r == 1 {
            return Ok(());
        }
        // SAFETY: ssl is live.
        let err = unsafe { aws_lc_sys::SSL_get_error(ssl.as_ptr(), r) };
        match err {
            aws_lc_sys::SSL_ERROR_WANT_READ => {
                tcp.readable()
                    .await
                    .map_err(|e| Error::Handshake(format!("waiting readable: {e}")))?;
                // libssl just observed EAGAIN on its BIO recv; tokio
                // didn't see that, so manually clear the cached readable
                // bit before looping.
                let _: io::Result<()> =
                    tcp.try_io(Interest::READABLE, || Err(io::ErrorKind::WouldBlock.into()));
            }
            aws_lc_sys::SSL_ERROR_WANT_WRITE => {
                tcp.writable()
                    .await
                    .map_err(|e| Error::Handshake(format!("waiting writable: {e}")))?;
                let _: io::Result<()> =
                    tcp.try_io(Interest::WRITABLE, || Err(io::ErrorKind::WouldBlock.into()));
            }
            aws_lc_sys::SSL_ERROR_ZERO_RETURN => {
                return Err(Error::Handshake(
                    "peer closed connection during handshake".into(),
                ))
            }
            _ => {
                return Err(Error::Handshake(format!(
                    "SSL_do_handshake: ssl_error={err} {}",
                    last_error()
                )))
            }
        }
    }
}
