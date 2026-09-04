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
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, Interest, ReadBuf};
use tokio::net::TcpStream;

use crate::error::{last_error, Error, KtlsError, Result};
use crate::ffi::Ssl;
use crate::session::{export_keying_material, KtlsEligibility, NegotiatedSession};

/// Established TLS session.
///
/// Created by [`crate::TlsAcceptor::accept`] (server) or
/// [`crate::TlsConnector::connect`] (client). Implements `AsyncRead` +
/// `AsyncWrite`; errors surface as plain [`io::Error`] so framed codecs
/// and `tokio::io::copy` work without conversion.
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
        Self {
            ssl,
            tcp,
            ktls_active: false,
            ktls_disabled,
        }
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
    /// runs on handshake completion and any kernel-side rejection
    /// (missing `tls` ULP, etc.) is silently swallowed. Observe
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
    /// `IneligibleCipher`, `TlsUlpUnavailable`, `SocketUnattachable`)
    /// so the stream silently continues on the userspace path.
    /// Propagates everything else (notably `SetSockOpt`, which happens
    /// *after* `TCP_ULP` has attached and leaves the socket in an
    /// unrecoverable state).
    ///
    /// On Linux the kernel `tls` module must be loaded
    /// (`sudo modprobe tls`, or add `tls` to `/etc/modules-load.d/`)
    /// for kTLS to engage. Container workloads need the *host* kernel
    /// to provide it. Call [`crate::host_ktls_available`] at startup
    /// to branch on host support, or check [`Self::ktls_active`]
    /// post-handshake to see whether the install actually happened.
    ///
    /// # Post-handshake records (TLS 1.3 `KeyUpdate`, alerts)
    ///
    /// Once kTLS is installed the kernel owns the record layer and
    /// AWS-LC's `SSL` object is no longer driving the wire. AWS-LC
    /// does **not** support rekeying after a kTLS attach: a peer-
    /// initiated TLS 1.3 `KeyUpdate` cannot be honoured because the
    /// new traffic secrets would have to be re-uploaded via
    /// `setsockopt(SOL_TLS, TLS_TX|TLS_RX, ...)` and the engine has
    /// no path to recompute them in-place. When the kernel receives
    /// any non-`application_data` record after attach it returns
    /// `EIO` on the next `read(2)`; that surfaces as an
    /// `io::ErrorKind::Other` from this stream's `AsyncRead` impl and
    /// the connection is effectively torn down. This is the strictest
    /// of the available options: `HAProxy` peeks at
    /// `TLS_GET_RECORD_TYPE` via `recvmsg` cmsg to swallow
    /// `NewSessionTicket` records and translate `close_notify`
    /// warnings into EOF, but Tokio's [`AsyncRead`] has no cmsg
    /// surface to plumb that through. Callers who need long-lived
    /// sessions across rekeys should disable kTLS on those
    /// connections via [`crate::ServerConfigBuilder::disable_ktls`] /
    /// [`crate::ClientConfigBuilder::disable_ktls`].
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
                | KtlsError::SocketUnattachable(_),
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
        if this.ktls_active {
            return ktls_poll_read(&this.tcp, cx, buf);
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
                aws_lc_sys::SSL_ERROR_WANT_READ => match poll_clear_read_ready(&this.tcp, cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                },
                aws_lc_sys::SSL_ERROR_WANT_WRITE => match poll_clear_write_ready(&this.tcp, cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                },
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
        if this.ktls_active {
            return ktls_poll_write(&this.tcp, cx, buf);
        }
        loop {
            #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
            let cap = buf.len().min(c_int::MAX as usize) as c_int;
            // SAFETY: ssl is live; buf is a readable buffer of length cap.
            let n = unsafe { aws_lc_sys::SSL_write(this.ssl.as_ptr(), buf.as_ptr().cast(), cap) };
            if n > 0 {
                #[allow(clippy::cast_sign_loss)]
                return Poll::Ready(Ok(n as usize));
            }
            // SAFETY: ssl is live.
            let err = unsafe { aws_lc_sys::SSL_get_error(this.ssl.as_ptr(), n) };
            match err {
                aws_lc_sys::SSL_ERROR_WANT_READ => match poll_clear_read_ready(&this.tcp, cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                },
                aws_lc_sys::SSL_ERROR_WANT_WRITE => match poll_clear_write_ready(&this.tcp, cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                },
                aws_lc_sys::SSL_ERROR_ZERO_RETURN => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "peer closed TLS session",
                    )))
                }
                _ => return Poll::Ready(Err(ssl_io_error("SSL_write", err))),
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // SSL writes go straight through to the socket via SSL_set_bio;
        // there is no userspace buffer to flush. Same after kTLS
        // install: the kernel buffers like any other TCP socket.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.ktls_active {
            // After kTLS install, libssl no longer knows about the
            // socket state, so `SSL_shutdown` would write a TLS alert
            // record that the kernel `tls` ULP would re-encrypt as
            // application_data and corrupt the stream. The kernel
            // `tls` ULP also does not emit close_notify on TCP FIN by
            // itself, so we just shut the write half down — the peer's
            // kTLS_RX surfaces a clean EOF. This is the standard kTLS
            // shutdown pattern.
            return Pin::new(&mut this.tcp).poll_shutdown(cx);
        }
        loop {
            // SAFETY: ssl is live.
            let r = unsafe { aws_lc_sys::SSL_shutdown(this.ssl.as_ptr()) };
            if r >= 0 {
                // 0 = our close_notify sent; 1 = peer's also seen.
                // Either is "done" from our side.
                return Poll::Ready(Ok(()));
            }
            // SAFETY: ssl is live.
            let err = unsafe { aws_lc_sys::SSL_get_error(this.ssl.as_ptr(), r) };
            match err {
                aws_lc_sys::SSL_ERROR_WANT_READ => match poll_clear_read_ready(&this.tcp, cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                },
                aws_lc_sys::SSL_ERROR_WANT_WRITE => match poll_clear_write_ready(&this.tcp, cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                },
                // Peer already sent close_notify, or the transport
                // returned EOF before our shutdown alert landed. Treat
                // as a clean shutdown.
                aws_lc_sys::SSL_ERROR_ZERO_RETURN | aws_lc_sys::SSL_ERROR_SYSCALL => {
                    return Poll::Ready(Ok(()));
                }
                _ => return Poll::Ready(Err(ssl_io_error("SSL_shutdown", err))),
            }
        }
    }
}

/// kTLS-mode `poll_read`: `read(2)` plaintext directly off the socket.
/// The kernel handles the AEAD record layer transparently.
fn ktls_poll_read(
    tcp: &TcpStream,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
) -> Poll<io::Result<()>> {
    loop {
        let unfilled = buf.initialize_unfilled();
        if unfilled.is_empty() {
            return Poll::Ready(Ok(()));
        }
        // `try_read` clears the cached readable bit on WouldBlock so the
        // subsequent `poll_read_ready` waits for a fresh OS notification
        // instead of busy-looping.
        match tcp.try_read(unfilled) {
            Ok(0) => return Poll::Ready(Ok(())), // EOF
            Ok(n) => {
                buf.advance(n);
                return Poll::Ready(Ok(()));
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => match tcp.poll_read_ready(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            },
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Poll::Ready(Err(e)),
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
    let detail = last_error();
    io::Error::other(format!("{op}: ssl_error={code} {detail}"))
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
