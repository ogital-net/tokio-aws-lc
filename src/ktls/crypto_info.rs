//! `#[repr(C)]` mirrors of `<linux/tls.h>` `tls12_crypto_info_*` layouts,
//! plus the constants the kernel UAPI keys them off.
//!
//! Sizes are pinned by compile-time `assert!`s in [`tests`]: the wire
//! layout is fixed by the kernel ABI and any drift here would silently
//! corrupt a setsockopt call, so we'd rather fail compilation than
//! discover a one-byte gap at runtime.
//!
//! Defined here, used from the Linux-only dispatcher in
//! [`super`]. The structs themselves are platform-neutral (just
//! `repr(C)` Plain-Old-Data) so they live in this submodule and can be
//! exercised by unit tests on any host.

#![allow(non_camel_case_types)]

/// `SOL_TLS` — kernel TLS setsockopt level (`include/uapi/linux/tls.h`).
#[cfg(target_os = "linux")]
pub const SOL_TLS: i32 = 282;
/// `TCP_ULP` — TCP-level setsockopt that selects an Upper Layer
/// Protocol. Passing `"tls"` flips this socket into kTLS mode.
#[cfg(target_os = "linux")]
pub const TCP_ULP: i32 = 31;
/// `SOL_TCP`. Hard-coded rather than pulled from `libc` to keep
/// the runtime dep surface bare.
#[cfg(target_os = "linux")]
pub const SOL_TCP: i32 = 6;

/// `TLS_TX` direction selector for `setsockopt(SOL_TLS, ...)`.
#[cfg(target_os = "linux")]
pub const TLS_TX: i32 = 1;
/// `TLS_RX` direction selector for `setsockopt(SOL_TLS, ...)`.
#[cfg(target_os = "linux")]
pub const TLS_RX: i32 = 2;

#[allow(dead_code)] // Used by Linux dispatcher and version-check tests.
pub const TLS_1_2_VERSION: u16 = 0x0303;
#[allow(dead_code)]
pub const TLS_1_3_VERSION: u16 = 0x0304;

#[cfg(target_os = "linux")]
pub const TLS_CIPHER_AES_GCM_128: u16 = 51;
#[cfg(target_os = "linux")]
pub const TLS_CIPHER_AES_GCM_256: u16 = 52;
#[cfg(target_os = "linux")]
pub const TLS_CIPHER_CHACHA20_POLY1305: u16 = 54;

// AES-GCM (both 128 and 256) UAPI sizes.
pub const AES_GCM_IV_LEN: usize = 8;
pub const AES_GCM_SALT_LEN: usize = 4;
pub const AES_GCM_128_KEY_LEN: usize = 16;
pub const AES_GCM_256_KEY_LEN: usize = 32;

// ChaCha20-Poly1305 UAPI sizes. The entire 96-bit nonce lives in
// `iv`; `salt` is empty (RFC 7905 has no implicit/explicit nonce
// split).
pub const CHACHA20_POLY1305_KEY_LEN: usize = 32;
pub const CHACHA20_POLY1305_IV_LEN: usize = 12;
pub const CHACHA20_POLY1305_SALT_LEN: usize = 0;

/// TLS record sequence number, big-endian.
pub const TLS_REC_SEQ_LEN: usize = 8;

/// Mirrors `struct tls_crypto_info` from `<linux/tls.h>` — the common
/// header on every `tls12_crypto_info_*`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct tls_crypto_info {
    pub version: u16,
    pub cipher_type: u16,
}

/// Mirrors `struct tls12_crypto_info_aes_gcm_128`. The kernel uses the
/// same struct for both TLS 1.2 and 1.3 AES-128-GCM; only
/// `info.version` and the IV/salt interpretation differ between the two.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct tls12_crypto_info_aes_gcm_128 {
    pub info: tls_crypto_info,
    pub iv: [u8; AES_GCM_IV_LEN],
    pub key: [u8; AES_GCM_128_KEY_LEN],
    pub salt: [u8; AES_GCM_SALT_LEN],
    pub rec_seq: [u8; TLS_REC_SEQ_LEN],
}

/// Mirrors `struct tls12_crypto_info_aes_gcm_256`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct tls12_crypto_info_aes_gcm_256 {
    pub info: tls_crypto_info,
    pub iv: [u8; AES_GCM_IV_LEN],
    pub key: [u8; AES_GCM_256_KEY_LEN],
    pub salt: [u8; AES_GCM_SALT_LEN],
    pub rec_seq: [u8; TLS_REC_SEQ_LEN],
}

/// Mirrors `struct tls12_crypto_info_chacha20_poly1305`. Salt is
/// zero-length: per RFC 7905 there is no implicit/explicit nonce split,
/// so the entire 12-byte static IV / derived nonce lives in `iv`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct tls12_crypto_info_chacha20_poly1305 {
    pub info: tls_crypto_info,
    pub iv: [u8; CHACHA20_POLY1305_IV_LEN],
    pub key: [u8; CHACHA20_POLY1305_KEY_LEN],
    pub salt: [u8; CHACHA20_POLY1305_SALT_LEN],
    pub rec_seq: [u8; TLS_REC_SEQ_LEN],
}

// Sizes are checked at compile time. Any mismatch with the kernel UAPI
// (e.g. someone "helpfully" reorders a field) breaks the build rather
// than producing a corrupted setsockopt call.
const _: () = assert!(std::mem::size_of::<tls_crypto_info>() == 4);
const _: () = assert!(std::mem::size_of::<tls12_crypto_info_aes_gcm_128>() == 40);
const _: () = assert!(std::mem::size_of::<tls12_crypto_info_aes_gcm_256>() == 56);
const _: () = assert!(std::mem::size_of::<tls12_crypto_info_chacha20_poly1305>() == 56);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_gcm_128_size() {
        // 4 (header) + 8 (iv) + 16 (key) + 4 (salt) + 8 (rec_seq) = 40.
        assert_eq!(std::mem::size_of::<tls12_crypto_info_aes_gcm_128>(), 40);
    }

    #[test]
    fn aes_gcm_256_size() {
        // 4 + 8 + 32 + 4 + 8 = 56.
        assert_eq!(std::mem::size_of::<tls12_crypto_info_aes_gcm_256>(), 56);
    }

    #[test]
    fn chacha20_poly1305_size() {
        // 4 + 12 + 32 + 0 + 8 = 56.
        assert_eq!(
            std::mem::size_of::<tls12_crypto_info_chacha20_poly1305>(),
            56
        );
    }

    #[test]
    fn version_constants_match_aws_lc() {
        assert_eq!(i32::from(TLS_1_2_VERSION), aws_lc_sys::TLS1_2_VERSION);
        assert_eq!(i32::from(TLS_1_3_VERSION), aws_lc_sys::TLS1_3_VERSION);
    }
}
