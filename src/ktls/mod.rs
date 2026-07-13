//! kTLS install: derive AEAD keys from a finished SSL handshake and
//! push them into the kernel via `setsockopt(SOL_TLS, TLS_TX/RX, ...)`.
//!
//! The crypto-info layouts and the cross-platform key derivation live
//! in [`crypto_info`] and [`derive`]; only the actual `setsockopt` /
//! socket-side plumbing is Linux-gated.
//!
//! On non-Linux targets [`install_ktls`] returns
//! [`KtlsError::Unsupported`] without touching the socket.

pub(crate) mod cipher;
pub(crate) mod crypto_info;
#[cfg(target_os = "linux")]
pub(crate) mod derive;

use std::os::raw::c_int;

use crate::error::{Error, KtlsError, Result};
use crate::ffi::Ssl;

use self::cipher::KtlsCipher;
#[cfg(target_os = "linux")]
use self::crypto_info::{
    tls12_crypto_info_aes_gcm_128, tls12_crypto_info_aes_gcm_256,
    tls12_crypto_info_chacha20_poly1305, tls_crypto_info, AES_GCM_128_KEY_LEN, AES_GCM_256_KEY_LEN,
    AES_GCM_SALT_LEN, CHACHA20_POLY1305_IV_LEN, CHACHA20_POLY1305_KEY_LEN, TLS_1_2_VERSION,
    TLS_1_3_VERSION, TLS_CIPHER_AES_GCM_128, TLS_CIPHER_AES_GCM_256, TLS_CIPHER_CHACHA20_POLY1305,
};
#[cfg(target_os = "linux")]
use self::derive::{
    hkdf_expand_label, is_server, sequences, split_tls12_key_block, tls12_key_block,
    tls13_traffic_secret, Direction, Hash,
};

/// Whether the host kernel exposes the `tls` ULP — i.e. whether
/// the auto-install path on accept/connect has a chance of engaging
/// on a session with a kTLS-eligible cipher.
///
/// Intended as a startup probe so consumers can branch on it (log a
/// warning, fall back to userspace AEAD, gate a metric, etc.) without
/// having to actually attempt an install on a real session.
///
/// # How the probe works
///
/// - **Non-Linux:** always returns `false`. kTLS has no analogue on
///   macOS or any other supported target.
/// - **Linux:** returns `true` iff `/proc/net/tls_stat` exists. That
///   file is created by `tls_init()` in the kernel module, so it is
///   present exactly when the `tls` module is loaded or
///   `CONFIG_TLS=y` is built in — which is the same condition that
///   `setsockopt(SOL_TCP, TCP_ULP, "tls")` checks. A real
///   `setsockopt` probe would need a connected loopback socket
///   (`tls_init` rejects non-`ESTABLISHED` sockets with `ENOTCONN`);
///   the proc-file check matches the same condition at zero syscalls.
///
/// This is a structural probe of the kernel's kTLS support, not of
/// the negotiated session. Whether a given handshake can actually be
/// offloaded also depends on the cipher — use
/// [`crate::TlsStream::ktls_eligibility`] on the post-handshake
/// stream for that check.
///
/// On a host where this returns `false`, the crate continues to work
/// in userspace-AEAD mode: handshakes, reads, and writes all go
/// through `libssl` as normal, and the auto-install path on
/// accept/connect silently no-ops (load the module with
/// `modprobe tls` or build the kernel with `CONFIG_TLS=y` to enable
/// kTLS).
#[must_use]
pub fn host_ktls_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        std::path::Path::new("/proc/net/tls_stat").exists()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// What the dispatcher wants to install. Returned per-direction so the
/// caller can hand them straight to `setsockopt`.
#[cfg(target_os = "linux")]
enum CryptoInfo {
    AesGcm128 {
        tx: tls12_crypto_info_aes_gcm_128,
        rx: tls12_crypto_info_aes_gcm_128,
    },
    AesGcm256 {
        tx: tls12_crypto_info_aes_gcm_256,
        rx: tls12_crypto_info_aes_gcm_256,
    },
    Chacha20Poly1305 {
        tx: tls12_crypto_info_chacha20_poly1305,
        rx: tls12_crypto_info_chacha20_poly1305,
    },
}

/// Derive TX/RX crypto-info blocks from a finished SSL handshake, then
/// push them into the kernel `tls` ULP on `fd`.
///
/// On non-Linux targets returns [`KtlsError::Unsupported`] and does not
/// touch the socket.
pub(crate) fn install_ktls(ssl: &Ssl, fd: c_int) -> Result<()> {
    let Some(cipher) = KtlsCipher::detect(ssl) else {
        // Build the diagnostic strings only on the error path; the
        // happy path never touches `KtlsEligibility`.
        // SAFETY: ssl is live per caller contract.
        let elig = unsafe { crate::session::KtlsEligibility::from_ssl(ssl) };
        return Err(Error::Ktls(KtlsError::IneligibleCipher {
            tls_version: elig.tls_version().to_owned(),
            cipher: elig.cipher().to_owned(),
        }));
    };

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (fd, cipher);
        Err(Error::Ktls(KtlsError::Unsupported))
    }
    #[cfg(target_os = "linux")]
    {
        let info = derive_crypto_info(ssl, cipher)?;
        linux::install(fd, &info).map_err(Error::Ktls)
    }
}

/// Derivation only — used by the dispatcher and by tests on non-Linux
/// hosts that want to exercise the key-block plumbing without
/// `setsockopt`-ing anything.
#[cfg(target_os = "linux")]
fn derive_crypto_info(ssl: &Ssl, cipher: KtlsCipher) -> Result<CryptoInfo> {
    let (write_seq, read_seq) = sequences(ssl);
    match cipher {
        KtlsCipher::Tls13Aes128Gcm => {
            let write_secret = tls13_traffic_secret(ssl, Direction::Write, 32)?;
            let read_secret = tls13_traffic_secret(ssl, Direction::Read, 32)?;
            let mut wk = [0u8; AES_GCM_128_KEY_LEN];
            let mut wi = [0u8; 12];
            let mut rk = [0u8; AES_GCM_128_KEY_LEN];
            let mut ri = [0u8; 12];
            hkdf_expand_label(Hash::Sha256, &write_secret, "key", &mut wk)?;
            hkdf_expand_label(Hash::Sha256, &write_secret, "iv", &mut wi)?;
            hkdf_expand_label(Hash::Sha256, &read_secret, "key", &mut rk)?;
            hkdf_expand_label(Hash::Sha256, &read_secret, "iv", &mut ri)?;
            Ok(CryptoInfo::AesGcm128 {
                tx: build_aes_gcm_128(TLS_1_3_VERSION, &wk, &wi[..4], &wi[4..], write_seq),
                rx: build_aes_gcm_128(TLS_1_3_VERSION, &rk, &ri[..4], &ri[4..], read_seq),
            })
        }
        KtlsCipher::Tls13Aes256Gcm => {
            let write_secret = tls13_traffic_secret(ssl, Direction::Write, 48)?;
            let read_secret = tls13_traffic_secret(ssl, Direction::Read, 48)?;
            let mut wk = [0u8; AES_GCM_256_KEY_LEN];
            let mut wi = [0u8; 12];
            let mut rk = [0u8; AES_GCM_256_KEY_LEN];
            let mut ri = [0u8; 12];
            hkdf_expand_label(Hash::Sha384, &write_secret, "key", &mut wk)?;
            hkdf_expand_label(Hash::Sha384, &write_secret, "iv", &mut wi)?;
            hkdf_expand_label(Hash::Sha384, &read_secret, "key", &mut rk)?;
            hkdf_expand_label(Hash::Sha384, &read_secret, "iv", &mut ri)?;
            Ok(CryptoInfo::AesGcm256 {
                tx: build_aes_gcm_256(TLS_1_3_VERSION, &wk, &wi[..4], &wi[4..], write_seq),
                rx: build_aes_gcm_256(TLS_1_3_VERSION, &rk, &ri[..4], &ri[4..], read_seq),
            })
        }
        KtlsCipher::Tls13Chacha20Poly1305 => {
            let write_secret = tls13_traffic_secret(ssl, Direction::Write, 32)?;
            let read_secret = tls13_traffic_secret(ssl, Direction::Read, 32)?;
            let mut wk = [0u8; CHACHA20_POLY1305_KEY_LEN];
            let mut wi = [0u8; CHACHA20_POLY1305_IV_LEN];
            let mut rk = [0u8; CHACHA20_POLY1305_KEY_LEN];
            let mut ri = [0u8; CHACHA20_POLY1305_IV_LEN];
            hkdf_expand_label(Hash::Sha256, &write_secret, "key", &mut wk)?;
            hkdf_expand_label(Hash::Sha256, &write_secret, "iv", &mut wi)?;
            hkdf_expand_label(Hash::Sha256, &read_secret, "key", &mut rk)?;
            hkdf_expand_label(Hash::Sha256, &read_secret, "iv", &mut ri)?;
            Ok(CryptoInfo::Chacha20Poly1305 {
                tx: build_chacha20_poly1305(TLS_1_3_VERSION, &wk, &wi, write_seq),
                rx: build_chacha20_poly1305(TLS_1_3_VERSION, &rk, &ri, read_seq),
            })
        }
        KtlsCipher::Tls12Aes128Gcm => {
            let server = is_server(ssl);
            // 2 * (key 16 + salt 4) = 40.
            let block = tls12_key_block(ssl, 40)?;
            let (wk, ws, rk, rs) = split_tls12_key_block(&block, 16, 4, server);
            Ok(CryptoInfo::AesGcm128 {
                tx: build_aes_gcm_128(TLS_1_2_VERSION, wk, ws, &write_seq.to_be_bytes(), write_seq),
                rx: build_aes_gcm_128(TLS_1_2_VERSION, rk, rs, &read_seq.to_be_bytes(), read_seq),
            })
        }
        KtlsCipher::Tls12Aes256Gcm => {
            let server = is_server(ssl);
            // 2 * (key 32 + salt 4) = 72.
            let block = tls12_key_block(ssl, 72)?;
            let (wk, ws, rk, rs) = split_tls12_key_block(&block, 32, 4, server);
            Ok(CryptoInfo::AesGcm256 {
                tx: build_aes_gcm_256(TLS_1_2_VERSION, wk, ws, &write_seq.to_be_bytes(), write_seq),
                rx: build_aes_gcm_256(TLS_1_2_VERSION, rk, rs, &read_seq.to_be_bytes(), read_seq),
            })
        }
        KtlsCipher::Tls12Chacha20Poly1305 => {
            let server = is_server(ssl);
            // 2 * (key 32 + iv 12) = 88. No implicit/explicit nonce
            // split per RFC 7905; the full 12-byte IV lives in `iv`.
            let block = tls12_key_block(ssl, 88)?;
            let (wk, wi, rk, ri) = split_tls12_key_block(&block, 32, 12, server);
            Ok(CryptoInfo::Chacha20Poly1305 {
                tx: build_chacha20_poly1305(TLS_1_2_VERSION, wk, wi, write_seq),
                rx: build_chacha20_poly1305(TLS_1_2_VERSION, rk, ri, read_seq),
            })
        }
    }
}

/// Verify libssl has no buffered data that the kernel would miss after
/// install (it would be silently dropped because the kernel takes over
/// the read path).
///
/// Uses `SSL_has_pending`, not `SSL_pending`: the latter only counts
/// already-*decrypted* bytes, so it returns 0 in the dangerous case
/// where the peer's first application record was coalesced into the
/// same TCP segment as the handshake `Finished`. `SSL_do_handshake`
/// pulls that whole segment off the socket into libssl's BIO, leaving
/// the trailing application record buffered but still *undecrypted* —
/// `SSL_pending` reports 0 while the bytes are sitting in libssl, about
/// to be stranded once the kernel owns the fd. `SSL_has_pending` also
/// reports buffered-but-undecrypted transport data, so it catches this.
///
/// NB: this crate never enables read-ahead (`SSL_set_read_ahead` /
/// `SSL_CTX_set_read_ahead`), so `SSL_has_pending` cannot spuriously
/// fire on a partial undecryptable record here — a non-zero result
/// always means real bytes the kernel would miss.
pub(crate) fn check_no_buffered_plaintext(ssl: &Ssl) -> Result<()> {
    // SAFETY: ssl is live.
    let has_pending = unsafe { aws_lc_sys::SSL_has_pending(ssl.as_ptr()) };
    if has_pending != 0 {
        // `SSL_pending` gives the decrypted-byte count for diagnostics;
        // it may legitimately be 0 here when only undecrypted transport
        // data is buffered (the coalesced-record case above).
        // SAFETY: ssl is live.
        let pending = unsafe { aws_lc_sys::SSL_pending(ssl.as_ptr()) };
        #[allow(clippy::cast_sign_loss)]
        let n = pending.max(0) as usize;
        return Err(Error::Ktls(KtlsError::BufferedPlaintext(n)));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn build_aes_gcm_128(
    version: u16,
    key: &[u8],
    salt: &[u8],
    iv: &[u8],
    rec_seq: u64,
) -> tls12_crypto_info_aes_gcm_128 {
    let mut out = tls12_crypto_info_aes_gcm_128 {
        info: tls_crypto_info {
            version,
            cipher_type: TLS_CIPHER_AES_GCM_128,
        },
        iv: [0; 8],
        key: [0; AES_GCM_128_KEY_LEN],
        salt: [0; AES_GCM_SALT_LEN],
        rec_seq: rec_seq.to_be_bytes(),
    };
    out.key.copy_from_slice(key);
    out.salt.copy_from_slice(salt);
    out.iv.copy_from_slice(iv);
    out
}

#[cfg(target_os = "linux")]
fn build_aes_gcm_256(
    version: u16,
    key: &[u8],
    salt: &[u8],
    iv: &[u8],
    rec_seq: u64,
) -> tls12_crypto_info_aes_gcm_256 {
    let mut out = tls12_crypto_info_aes_gcm_256 {
        info: tls_crypto_info {
            version,
            cipher_type: TLS_CIPHER_AES_GCM_256,
        },
        iv: [0; 8],
        key: [0; AES_GCM_256_KEY_LEN],
        salt: [0; AES_GCM_SALT_LEN],
        rec_seq: rec_seq.to_be_bytes(),
    };
    out.key.copy_from_slice(key);
    out.salt.copy_from_slice(salt);
    out.iv.copy_from_slice(iv);
    out
}

#[cfg(target_os = "linux")]
fn build_chacha20_poly1305(
    version: u16,
    key: &[u8],
    iv: &[u8],
    rec_seq: u64,
) -> tls12_crypto_info_chacha20_poly1305 {
    let mut out = tls12_crypto_info_chacha20_poly1305 {
        info: tls_crypto_info {
            version,
            cipher_type: TLS_CIPHER_CHACHA20_POLY1305,
        },
        iv: [0; CHACHA20_POLY1305_IV_LEN],
        key: [0; CHACHA20_POLY1305_KEY_LEN],
        salt: [],
        rec_seq: rec_seq.to_be_bytes(),
    };
    out.key.copy_from_slice(key);
    out.iv.copy_from_slice(iv);
    out
}

#[cfg(target_os = "linux")]
mod linux {
    //! `setsockopt` plumbing. Kept in a private submodule so the only
    //! `unsafe` syscall surface for kTLS lives in one place.

    use std::io;
    use std::os::raw::{c_int, c_void};

    use super::crypto_info::{SOL_TCP, SOL_TLS, TCP_ULP, TLS_RX, TLS_TX};
    use super::CryptoInfo;
    use crate::error::KtlsError;

    // We deliberately do not pull `libc`. `setsockopt` is a stable Linux
    // syscall with a fixed signature; binding it directly costs four
    // lines and keeps the runtime dep surface to `aws-lc-sys` + `tokio`.
    #[allow(non_camel_case_types)]
    type socklen_t = u32;

    // Stable Linux errno values; hard-coded for the same reason we
    // hand-bind `setsockopt`.
    const ENOENT: i32 = 2;
    const ENOPROTOOPT: i32 = 92;
    const ENOTCONN: i32 = 107;
    const EISCONN: i32 = 106;
    const EBUSY: i32 = 16;

    extern "C" {
        fn setsockopt(
            sockfd: c_int,
            level: c_int,
            optname: c_int,
            optval: *const c_void,
            optlen: socklen_t,
        ) -> c_int;
    }

    pub(super) fn install(fd: c_int, info: &CryptoInfo) -> Result<(), KtlsError> {
        set_ulp_tls(fd).map_err(classify_ulp_error)?;
        match info {
            CryptoInfo::AesGcm128 { tx, rx } => {
                set_crypto_info(fd, TLS_TX, tx).map_err(KtlsError::SetSockOpt)?;
                set_crypto_info(fd, TLS_RX, rx).map_err(KtlsError::SetSockOpt)?;
            }
            CryptoInfo::AesGcm256 { tx, rx } => {
                set_crypto_info(fd, TLS_TX, tx).map_err(KtlsError::SetSockOpt)?;
                set_crypto_info(fd, TLS_RX, rx).map_err(KtlsError::SetSockOpt)?;
            }
            CryptoInfo::Chacha20Poly1305 { tx, rx } => {
                set_crypto_info(fd, TLS_TX, tx).map_err(KtlsError::SetSockOpt)?;
                set_crypto_info(fd, TLS_RX, rx).map_err(KtlsError::SetSockOpt)?;
            }
        }
        Ok(())
    }

    /// `ENOENT` is what the kernel returns from `__tcp_ulp_find_autoload`
    /// when the `tls` module isn't loaded and auto-loading is denied or
    /// unavailable (e.g. inside an unprivileged container).
    /// `ENOPROTOOPT` shows up on older kernels (< 4.13) that don't know
    /// `TCP_ULP` at all.
    ///
    /// `ENOTCONN`, `EISCONN`, and `EBUSY` are *socket-state* errors
    /// from `__tcp_ulp_init`: the host kernel supports kTLS, but this
    /// particular socket is not in the right state to accept a ULP
    /// attach (typically because the peer FIN'd before we could call
    /// `setsockopt`, or another ULP is already attached). The
    /// auto-install path treats these as non-fatal so a benign race
    /// during TCP teardown does not kill the connection.
    ///
    /// Every other errno is a different failure mode and stays
    /// generic.
    pub(super) fn classify_ulp_error(e: io::Error) -> KtlsError {
        match e.raw_os_error() {
            Some(ENOENT | ENOPROTOOPT) => KtlsError::TlsUlpUnavailable(e),
            Some(ENOTCONN | EISCONN | EBUSY) => KtlsError::SocketUnattachable(e),
            _ => KtlsError::SetSockOpt(e),
        }
    }

    fn set_ulp_tls(fd: c_int) -> io::Result<()> {
        // `"tls"` literal, not NUL-terminated — the kernel takes an
        // explicit length and matches on prefix.
        let name = b"tls";
        // SAFETY: `fd` is a valid open socket fd. `name` is a 3-byte
        // readable buffer; we pass its length explicitly.
        let rc = unsafe {
            setsockopt(
                fd,
                SOL_TCP,
                TCP_ULP,
                name.as_ptr().cast(),
                socklen_t::try_from(name.len()).expect("3 fits in u32"),
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn set_crypto_info<T>(fd: c_int, direction: c_int, info: &T) -> io::Result<()> {
        let len = std::mem::size_of::<T>();
        // SAFETY: `fd` is a valid socket fd already in `tls` ULP mode.
        // `info` is a fully-initialised `#[repr(C)]` struct of exactly
        // `len` bytes; the kernel copies it in and stores it internally.
        let rc = unsafe {
            setsockopt(
                fd,
                SOL_TLS,
                direction,
                std::ptr::from_ref::<T>(info).cast(),
                socklen_t::try_from(len).expect("crypto_info fits in u32"),
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn classify_enoent_is_ulp_unavailable() {
            let e = io::Error::from_raw_os_error(ENOENT);
            assert!(matches!(
                classify_ulp_error(e),
                KtlsError::TlsUlpUnavailable(_)
            ));
        }

        #[test]
        fn classify_enoprotoopt_is_ulp_unavailable() {
            let e = io::Error::from_raw_os_error(ENOPROTOOPT);
            assert!(matches!(
                classify_ulp_error(e),
                KtlsError::TlsUlpUnavailable(_)
            ));
        }

        #[test]
        fn classify_enotconn_is_socket_unattachable() {
            let e = io::Error::from_raw_os_error(ENOTCONN);
            assert!(matches!(
                classify_ulp_error(e),
                KtlsError::SocketUnattachable(_)
            ));
        }

        #[test]
        fn classify_eisconn_is_socket_unattachable() {
            let e = io::Error::from_raw_os_error(EISCONN);
            assert!(matches!(
                classify_ulp_error(e),
                KtlsError::SocketUnattachable(_)
            ));
        }

        #[test]
        fn classify_other_errno_stays_generic() {
            let e = io::Error::from_raw_os_error(13); // EACCES
            assert!(matches!(classify_ulp_error(e), KtlsError::SetSockOpt(_)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::host_ktls_available;

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn host_ktls_available_is_false_on_non_linux() {
        assert!(!host_ktls_available());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn host_ktls_available_matches_proc_file() {
        // The function is documented as a heuristic over
        // /proc/net/tls_stat; lock that contract in so a future
        // refactor cannot drift away silently.
        let direct = std::path::Path::new("/proc/net/tls_stat").exists();
        assert_eq!(host_ktls_available(), direct);
    }

    #[test]
    fn host_ktls_available_is_stable() {
        // Two consecutive calls must agree (idempotent, no hidden
        // state). The actual value depends on the host.
        assert_eq!(host_ktls_available(), host_ktls_available());
    }
}
