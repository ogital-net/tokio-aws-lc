//! Per-direction key/IV/salt/sequence derivation for kTLS install.
//!
//! TLS 1.3 (RFC 8446 §7.3): pull the per-direction application traffic
//! secret out of libssl, run HKDF-Expand-Label with labels `"key"` and
//! `"iv"` to derive the AEAD key and the 12-byte static IV.
//!
//! TLS 1.2 (RFC 5246 §6.3, RFC 5288 §3, RFC 7905 §2): expand a single
//! PRF key block from the master secret, split into
//! `client_write_key | server_write_key | client_write_IV | server_write_IV`
//! (no MAC keys — AEAD ciphersuites have zero-length MAC keys), and
//! pick the right half based on whether this endpoint is the server
//! or client. The "write" direction from this endpoint's perspective
//! is what becomes `TLS_TX`.
//!
//! Pure logic: this module does not touch sockets or the kernel. It is
//! cross-platform on purpose so the HKDF-Expand-Label vectors can be
//! unit-tested on macOS too.

use crate::error::{last_error, Error, Result};
use crate::ffi::Ssl;

/// Hash function for [`hkdf_expand_label`].
#[derive(Debug, Clone, Copy)]
pub(crate) enum Hash {
    Sha256,
    Sha384,
}

impl Hash {
    fn md(self) -> *const aws_lc_sys::EVP_MD {
        // SAFETY: `EVP_sha256` / `EVP_sha384` return static
        // `EVP_MD *` pointers valid for the program's lifetime.
        unsafe {
            match self {
                Self::Sha256 => aws_lc_sys::EVP_sha256(),
                Self::Sha384 => aws_lc_sys::EVP_sha384(),
            }
        }
    }
}

/// TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1):
///
/// ```text
/// HkdfLabel = {
///     uint16 length        = Length;
///     opaque label<7..255> = "tls13 " + Label;
///     opaque context<0..255> = "";   // empty
/// }
/// HKDF-Expand-Label(Secret, Label, "", Length)
///   = HKDF-Expand(Secret, HkdfLabel, Length)
/// ```
///
/// Context is always empty for the `"key"` and `"iv"` derivations the
/// kTLS install path needs, so it's not exposed.
pub(crate) fn hkdf_expand_label(
    hash: Hash,
    secret: &[u8],
    label: &str,
    out: &mut [u8],
) -> Result<()> {
    // Construct HkdfLabel.
    let full_label_len = "tls13 ".len() + label.len();
    assert!(full_label_len <= 255, "kTLS labels fit in one byte");
    let mut info = Vec::with_capacity(2 + 1 + full_label_len + 1);
    let len_be = u16::try_from(out.len())
        .expect("HKDF-Expand-Label output length fits in u16")
        .to_be_bytes();
    info.extend_from_slice(&len_be);
    #[allow(clippy::cast_possible_truncation)]
    info.push(full_label_len as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label.as_bytes());
    info.push(0); // empty context

    // SAFETY: out/secret/info buffers all describe valid memory of
    // their stated lengths; `md` is a static AWS-LC EVP_MD pointer.
    let rc = unsafe {
        aws_lc_sys::HKDF_expand(
            out.as_mut_ptr(),
            out.len(),
            hash.md(),
            secret.as_ptr(),
            secret.len(),
            info.as_ptr(),
            info.len(),
        )
    };
    if rc == 1 {
        Ok(())
    } else {
        Err(Error::Init(format!(
            "HKDF_expand: rc={rc} {}",
            last_error()
        )))
    }
}

/// Which side's traffic secret we want.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Direction {
    /// The secret used to encrypt records leaving this endpoint
    /// (becomes `TLS_TX`).
    Write,
    /// The secret used to decrypt records arriving at this endpoint
    /// (becomes `TLS_RX`).
    Read,
}

/// Pull a TLS 1.3 traffic secret of the given hash's output length.
/// Errors out on length mismatch — the caller pins the size against
/// the negotiated hash.
pub(crate) fn tls13_traffic_secret(
    ssl: &Ssl,
    dir: Direction,
    expected_len: usize,
) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; 48]; // SHA-384 ceiling
    let mut got = buf.len();
    // SAFETY: ssl is live; both buffer + length out-params point at
    // owned local storage.
    let rc = unsafe {
        match dir {
            Direction::Write => aws_lc_sys::SSL_get_write_traffic_secret(
                ssl.as_ptr(),
                buf.as_mut_ptr(),
                &raw mut got,
            ),
            Direction::Read => aws_lc_sys::SSL_get_read_traffic_secret(
                ssl.as_ptr(),
                buf.as_mut_ptr(),
                &raw mut got,
            ),
        }
    };
    if rc != 1 || got != expected_len {
        return Err(Error::Init(format!(
            "SSL_get_{dir:?}_traffic_secret: rc={rc} len={got} want={expected_len}"
        )));
    }
    buf.truncate(got);
    Ok(buf)
}

/// Read a TLS 1.2 key block of the requested length out of libssl.
/// Wraps `SSL_generate_key_block`, which expands
/// `PRF(master_secret, "key expansion", server_random || client_random)`
/// into the requested number of bytes.
pub(crate) fn tls12_key_block(ssl: &Ssl, len: usize) -> Result<Vec<u8>> {
    let mut block = vec![0u8; len];
    // SAFETY: ssl is live; `block` is a writable buffer of exactly
    // `len` bytes that `SSL_generate_key_block` fills on success.
    let rc = unsafe {
        aws_lc_sys::SSL_generate_key_block(ssl.as_ptr(), block.as_mut_ptr(), block.len())
    };
    if rc != 1 {
        return Err(Error::Init(format!(
            "SSL_generate_key_block: rc={rc} {}",
            last_error()
        )));
    }
    Ok(block)
}

/// `true` if this endpoint is acting as the TLS server.
pub(crate) fn is_server(ssl: &Ssl) -> bool {
    // SAFETY: ssl is live.
    let v = unsafe { aws_lc_sys::SSL_is_server(ssl.as_ptr()) };
    v != 0
}

/// Current next-to-use record sequence numbers, for seeding `rec_seq`.
pub(crate) fn sequences(ssl: &Ssl) -> (u64, u64) {
    // SAFETY: ssl is live; both calls are pure reads returning u64.
    let write = unsafe { aws_lc_sys::SSL_get_write_sequence(ssl.as_ptr()) };
    // SAFETY: same.
    let read = unsafe { aws_lc_sys::SSL_get_read_sequence(ssl.as_ptr()) };
    (write, read)
}

/// Split a TLS 1.2 key block of the shape
/// `client_write_key(K) | server_write_key(K) | client_write_iv(I) | server_write_iv(I)`
/// into `(write_key, write_iv, read_key, read_iv)` from this endpoint's
/// perspective. `is_server` picks which half is "ours" for writing.
pub(crate) fn split_tls12_key_block(
    block: &[u8],
    key_len: usize,
    iv_len: usize,
    is_server: bool,
) -> (&[u8], &[u8], &[u8], &[u8]) {
    debug_assert_eq!(block.len(), 2 * (key_len + iv_len));
    let (client_key, rest) = block.split_at(key_len);
    let (server_key, rest) = rest.split_at(key_len);
    let (client_iv, server_iv) = rest.split_at(iv_len);
    if is_server {
        (server_key, server_iv, client_key, client_iv)
    } else {
        (client_key, client_iv, server_key, server_iv)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// HKDF-Expand-Label with an all-zero secret, label `"key"`, length 16.
    /// Reference value computed independently with Python's `hashlib` /
    /// `hmac` (info = `00 10 09 "tls13 key" 00`, then `HMAC-SHA256(0^32,
    /// info || 0x01)`, truncated to 16 bytes).
    #[test]
    fn hkdf_expand_label_sha256_known_answer_key() {
        let secret = [0u8; 32];
        let mut out = [0u8; 16];
        hkdf_expand_label(Hash::Sha256, &secret, "key", &mut out).unwrap();
        let expected: [u8; 16] = [
            0xcb, 0xee, 0x75, 0x71, 0xc6, 0x11, 0x03, 0x9c, 0xa3, 0x27, 0xa2, 0xe8, 0x79, 0xdf,
            0xcd, 0x45,
        ];
        assert_eq!(out, expected);
    }

    /// SHA-384 sibling of the above; same all-zero-secret pattern, 32-byte
    /// output, label `"key"`. Computed with the same Python script swapped
    /// to `hashlib.sha384`.
    #[test]
    fn hkdf_expand_label_sha384_known_answer_key() {
        let secret = [0u8; 48];
        let mut out = [0u8; 32];
        hkdf_expand_label(Hash::Sha384, &secret, "key", &mut out).unwrap();
        // First 32 bytes of HMAC-SHA384(0^48, "\x00\x20\x09tls13 key\x00\x01").
        let expected: [u8; 32] = [
            0xf6, 0x03, 0xd6, 0x8c, 0xd6, 0xfc, 0xca, 0xbb, 0xaa, 0x49, 0x69, 0xa9, 0xa6, 0x66,
            0x14, 0x34, 0xe0, 0x18, 0xf2, 0x96, 0xf4, 0xcd, 0x03, 0x69, 0xc9, 0x34, 0x36, 0x3a,
            0x58, 0x9a, 0x69, 0xea,
        ];
        assert_eq!(out, expected);
    }

    #[test]
    fn hkdf_expand_label_truncates() {
        let secret = [0xab; 32];
        let mut out = [0u8; 12];
        hkdf_expand_label(Hash::Sha256, &secret, "iv", &mut out).unwrap();
        // Just verify it ran and wrote 12 bytes (non-zero in practice).
        assert!(out.iter().any(|&b| b != 0));
    }

    #[test]
    fn split_tls12_key_block_server_perspective() {
        // 2 * (key=4 + iv=2) = 12 bytes.
        let block: [u8; 12] = [
            0x11, 0x11, 0x11, 0x11, // client_key
            0x22, 0x22, 0x22, 0x22, // server_key
            0xaa, 0xaa, // client_iv
            0xbb, 0xbb, // server_iv
        ];
        let (wk, wi, rk, ri) = split_tls12_key_block(&block, 4, 2, true);
        assert_eq!(wk, &[0x22; 4]);
        assert_eq!(wi, &[0xbb; 2]);
        assert_eq!(rk, &[0x11; 4]);
        assert_eq!(ri, &[0xaa; 2]);
    }

    #[test]
    fn split_tls12_key_block_client_perspective() {
        let block: [u8; 12] = [
            0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22, 0xaa, 0xaa, 0xbb, 0xbb,
        ];
        let (wk, wi, rk, ri) = split_tls12_key_block(&block, 4, 2, false);
        assert_eq!(wk, &[0x11; 4]);
        assert_eq!(wi, &[0xaa; 2]);
        assert_eq!(rk, &[0x22; 4]);
        assert_eq!(ri, &[0xbb; 2]);
    }
}
