//! Crate-wide error type and AWS-LC error-queue drainer.
//!
//! [`Error`] is hand-rolled rather than `thiserror`-derived so the crate
//! pulls no extra runtime dependency for a small surface. Variants are
//! lifecycle-ordered: callers typically see `Init` once at startup, then
//! `Handshake` per connection, then `Io` (and on Linux `Ktls`) on the
//! steady-state path. The `AsyncRead` / `AsyncWrite` impls on `TlsStream`
//! return plain `std::io::Error` so framed codecs and `tokio::io::copy`
//! work without conversion; this enum is for the parts of the API that
//! are *not* on the read/write hot path.

use std::ffi::CStr;
use std::fmt;
use std::io;
use std::os::raw::c_int;

/// Top-level error returned from the crate's non-`AsyncRead`/`AsyncWrite`
/// surface (config building, handshake driving, kTLS install).
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Configuration-time failure: `SSL_CTX_new`, PEM parsing,
    /// cipher list rejection, parameter validation, etc.
    Init(String),
    /// Handshake failed before the first plaintext byte moved.
    Handshake(String),
    /// Steady-state IO failure; wraps the underlying `io::Error`.
    Io(io::Error),
    /// kTLS install failure or precondition violation.
    Ktls(KtlsError),
}

/// kTLS-specific failure modes. Returned through [`Error::Ktls`] from
/// the auto-install path on accept/connect and any post-attach
/// record-type surfacing.
#[derive(Debug)]
#[non_exhaustive]
pub enum KtlsError {
    /// Platform does not support kTLS (e.g. macOS).
    Unsupported,
    /// Negotiated cipher / TLS version cannot be offloaded.
    IneligibleCipher { tls_version: String, cipher: String },
    /// libssl has buffered data — decrypted plaintext, or undecrypted
    /// transport bytes (e.g. the peer's first application record
    /// coalesced into the handshake's final TCP segment) — sitting in
    /// its internal buffer at the moment of install. Installing kTLS
    /// now would silently drop those bytes because the kernel takes
    /// over the read path and only sees what arrives on the wire
    /// afterwards. The payload is the number of *decrypted* bytes
    /// libssl had buffered (`SSL_pending`), which may be 0 when only
    /// undecrypted transport data is present.
    BufferedPlaintext(usize),
    /// The kernel rejected `setsockopt(SOL_TCP, TCP_ULP, "tls")` with
    /// an errno that indicates the `tls` Upper Layer Protocol is not
    /// available on this host (typically `ENOENT` or `ENOPROTOOPT`).
    /// In practice this means the `tls` kernel module is not loaded
    /// or the kernel was built without `CONFIG_TLS`.
    ///
    /// Fix: `sudo modprobe tls` (or add `tls` to
    /// `/etc/modules-load.d/`). Inside a container, the *host* kernel
    /// must provide the module — `modprobe` from inside the container
    /// will not help.
    TlsUlpUnavailable(io::Error),
    /// The `tls` ULP exists on the host, but the kernel refused to
    /// attach it to *this particular socket* (typically `ENOTCONN`
    /// when the peer FIN'd before we could attach, or `EISCONN`/`EBUSY`
    /// in races that come up on very short-lived connections). The
    /// kernel's `__tcp_ulp_init` requires `TCP_ESTABLISHED` and rejects
    /// anything else.
    ///
    /// Distinct from [`Self::TlsUlpUnavailable`] because the host
    /// itself is fine; the auto-install path treats this as non-fatal
    /// and keeps the stream on userspace AEAD so callers don't lose
    /// connections to benign races.
    SocketUnattachable(io::Error),
    /// `setsockopt(SOL_TLS, TLS_TX / TLS_RX, ...)` failed with the
    /// wrapped errno (e.g. kernel too old for the selected cipher).
    SetSockOpt(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Init(m) => write!(f, "tls init: {m}"),
            Self::Handshake(m) => write!(f, "tls handshake: {m}"),
            Self::Io(e) => write!(f, "tls io: {e}"),
            Self::Ktls(e) => write!(f, "ktls: {e}"),
        }
    }
}

impl fmt::Display for KtlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => f.write_str("kTLS is not supported on this platform"),
            Self::IneligibleCipher {
                tls_version,
                cipher,
            } => write!(
                f,
                "negotiated session is not kTLS-eligible ({tls_version} / {cipher})"
            ),
            Self::BufferedPlaintext(n) => write!(
                f,
                "libssl has {n} bytes of buffered plaintext; kTLS install would lose them"
            ),
            Self::TlsUlpUnavailable(e) => write!(
                f,
                "kernel `tls` ULP unavailable ({e}); load it with `modprobe tls` \
                 or ensure the host kernel was built with CONFIG_TLS"
            ),
            Self::SocketUnattachable(e) => write!(
                f,
                "kernel rejected TCP_ULP attach on this socket ({e}); \
                 typically a transient race with TCP teardown"
            ),
            Self::SetSockOpt(e) => write!(f, "setsockopt failed: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Ktls(e) => Some(e),
            Self::Init(_) | Self::Handshake(_) => None,
        }
    }
}

impl std::error::Error for KtlsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SetSockOpt(e) | Self::TlsUlpUnavailable(e) | Self::SocketUnattachable(e) => {
                Some(e)
            }
            Self::Unsupported | Self::IneligibleCipher { .. } | Self::BufferedPlaintext(_) => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Convenience [`Result`] alias that defaults the error to crate [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Drain a single error out of the AWS-LC thread-local error queue and
/// return it as an owned, human-readable string. After this call the
/// queue is empty.
///
/// Call this immediately after any fallible AWS-LC FFI returns its sentinel
/// (`NULL`, `0`, `<= 0` depending on the function). Leaving entries in the
/// queue is the most common foot-gun in the OpenSSL ABI: the next failing
/// call's diagnostic gets prepended with a stale code from a previous
/// failure on the same thread.
///
/// Returns `"(no error queued)"` when the queue was already empty — useful
/// only for diagnostic strings; treat it as a bug if the call site really
/// expected an error.
#[must_use]
pub fn last_error() -> String {
    // SAFETY: ERR_get_error has no arguments and is documented to return 0
    // when the per-thread queue is empty.
    let code = unsafe { aws_lc_sys::ERR_get_error() };
    if code == 0 {
        return "(no error queued)".into();
    }
    format_and_clear(code)
}

/// Render a single already-fetched packed error code to a human-readable
/// string, then drain any remaining queue entries so they cannot leak into
/// the next call.
///
/// Shared by [`last_error`] (formats whatever `ERR_get_error` pops) and
/// [`pem_eof_or_err`] (formats the exact entry it just classified via
/// `ERR_peek_last_error`, rather than popping a possibly-different entry
/// off the front of the queue).
fn format_and_clear(code: u32) -> String {
    let mut buf = [0u8; 256];
    // SAFETY: `buf` describes a writable slice of `buf.len()` bytes.
    // `ERR_error_string_n` writes a NUL-terminated string of at most `len`
    // bytes (truncating if necessary). `code` is a packed error value the
    // caller already obtained from the thread-local error queue.
    unsafe {
        aws_lc_sys::ERR_error_string_n(code, buf.as_mut_ptr().cast(), buf.len());
    }

    // Drain any remaining entries so they cannot leak into the next call.
    // SAFETY: ERR_clear_error has no arguments.
    unsafe {
        aws_lc_sys::ERR_clear_error();
    }

    let cstr = CStr::from_bytes_until_nul(&buf).unwrap_or(c"(malformed error string)");
    cstr.to_string_lossy().into_owned()
}

/// After a `PEM_read_bio_*` function returns NULL, decide whether the
/// queued error is the benign end-of-stream marker
/// (`(ERR_LIB_PEM, PEM_R_NO_START_LINE)`) or a real parse failure.
///
/// On EOF: drains the queue and returns `Ok(())`. On any other error:
/// formats and drains the same entry just classified (via
/// `ERR_peek_last_error`) and returns
/// `Err(Error::Init(format!("{label}: {detail}")))` so a corrupt
/// trailing certificate cannot be silently treated as "end of bundle".
pub(crate) fn pem_eof_or_err(label: &str) -> Result<()> {
    // SAFETY: `ERR_peek_last_error` takes no arguments and returns the
    // most recently queued error packed code (0 if the queue is empty).
    let packed = unsafe { aws_lc_sys::ERR_peek_last_error() };
    if packed == 0 {
        // No error queued at all — treat as clean EOF.
        return Ok(());
    }
    // OpenSSL-style packed-error layout (matches aws-lc-sys's
    // ERR_GET_LIB_RUST / ERR_GET_REASON_RUST helpers — which bindgen
    // surfaces but aws-lc does not export as link-time symbols).
    // Library is the top byte; reason is the low 12 bits.
    #[allow(clippy::cast_possible_wrap)]
    let lib = ((packed >> 24) & 0xff) as c_int;
    #[allow(clippy::cast_possible_wrap)]
    let reason = (packed & 0xfff) as c_int;
    if lib == aws_lc_sys::ERR_LIB_PEM && reason == aws_lc_sys::PEM_R_NO_START_LINE {
        // SAFETY: ERR_clear_error has no arguments.
        unsafe {
            aws_lc_sys::ERR_clear_error();
        }
        Ok(())
    } else {
        // Format the exact entry we just classified (`packed`, from
        // `ERR_peek_last_error`) instead of calling `last_error()`, which
        // pops via `ERR_get_error` (the *oldest* queued entry). If more
        // than one error was pushed for this failure the two would
        // disagree, reporting an unrelated error message for the very
        // entry we just decided was non-benign.
        Err(Error::Init(format!(
            "{label}: {}",
            format_and_clear(packed)
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_queue_returns_sentinel() {
        // Make sure the queue is clean (the test runner shares state with
        // any earlier test that touched aws-lc).
        // SAFETY: ERR_clear_error has no arguments.
        unsafe {
            aws_lc_sys::ERR_clear_error();
        }
        assert_eq!(last_error(), "(no error queued)");
    }

    #[test]
    fn display_includes_inner_message() {
        let err = Error::Init("bad cert".into());
        assert!(format!("{err}").contains("bad cert"));
    }

    #[test]
    fn ktls_unsupported_display() {
        let err = Error::Ktls(KtlsError::Unsupported);
        let s = format!("{err}");
        assert!(s.contains("ktls"), "got: {s}");
        assert!(s.contains("not supported"), "got: {s}");
    }

    #[test]
    fn io_error_round_trip_via_from() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionReset, "reset");
        let e: Error = io_err.into();
        assert!(matches!(e, Error::Io(_)));
    }

    #[test]
    fn handshake_display() {
        let s = format!("{}", Error::Handshake("bad alert".into()));
        assert!(s.starts_with("tls handshake:"), "got: {s}");
        assert!(s.contains("bad alert"), "got: {s}");
    }

    #[test]
    fn io_display_wraps_inner() {
        let inner = io::Error::new(io::ErrorKind::ConnectionReset, "boom");
        let s = format!("{}", Error::Io(inner));
        assert!(s.starts_with("tls io:"), "got: {s}");
        assert!(s.contains("boom"), "got: {s}");
    }

    #[test]
    fn ktls_ineligible_cipher_display() {
        let e = Error::Ktls(KtlsError::IneligibleCipher {
            tls_version: "TLSv1.2".into(),
            cipher: "ECDHE-ECDSA-AES128-SHA".into(),
        });
        let s = format!("{e}");
        assert!(s.contains("TLSv1.2"), "got: {s}");
        assert!(s.contains("ECDHE-ECDSA-AES128-SHA"), "got: {s}");
    }

    #[test]
    fn ktls_buffered_plaintext_display() {
        let e = KtlsError::BufferedPlaintext(17);
        let s = format!("{e}");
        assert!(s.contains("17"), "got: {s}");
    }

    #[test]
    fn ktls_setsockopt_display_and_source() {
        let inner = io::Error::from_raw_os_error(13); // EACCES
        let ke = KtlsError::SetSockOpt(inner);
        let s = format!("{ke}");
        assert!(s.starts_with("setsockopt failed:"), "got: {s}");
        assert!(std::error::Error::source(&ke).is_some());
        // Wrap and exercise Error::source for the Ktls arm too.
        let e = Error::Ktls(KtlsError::SetSockOpt(io::Error::from_raw_os_error(13)));
        assert!(std::error::Error::source(&e).is_some());
    }

    #[test]
    fn ktls_tls_ulp_unavailable_display_mentions_modprobe() {
        let inner = io::Error::from_raw_os_error(2); // ENOENT
        let ke = KtlsError::TlsUlpUnavailable(inner);
        let s = format!("{ke}");
        assert!(s.contains("modprobe tls"), "got: {s}");
        assert!(s.contains("CONFIG_TLS"), "got: {s}");
        assert!(std::error::Error::source(&ke).is_some());
    }

    #[test]
    fn error_source_io_some_init_none() {
        let io_err = Error::Io(io::Error::other("x"));
        assert!(std::error::Error::source(&io_err).is_some());
        let init = Error::Init("x".into());
        assert!(std::error::Error::source(&init).is_none());
        let hs = Error::Handshake("x".into());
        assert!(std::error::Error::source(&hs).is_none());
    }

    #[test]
    fn ktls_error_source_only_for_setsockopt() {
        assert!(std::error::Error::source(&KtlsError::Unsupported).is_none());
        assert!(std::error::Error::source(&KtlsError::BufferedPlaintext(1)).is_none());
        assert!(std::error::Error::source(&KtlsError::IneligibleCipher {
            tls_version: "x".into(),
            cipher: "y".into(),
        })
        .is_none());
        assert!(std::error::Error::source(&KtlsError::TlsUlpUnavailable(
            io::Error::from_raw_os_error(2)
        ))
        .is_some());
    }
}
