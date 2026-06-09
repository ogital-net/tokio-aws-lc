//! Typed identification of the negotiated (TLS version, AEAD cipher)
//! pair from a finished SSL handshake.
//!
//! Eligibility is a structural property of the negotiation: only AEAD
//! suites (`AES-GCM` and `ChaCha20-Poly1305`) over TLS 1.2 or 1.3 can
//! be offloaded to the Linux `tls` ULP. Everything else (CBC-SHA, RC4,
//! anything older) is reported as `None` and never reaches the
//! `setsockopt` path.
//!
//! Matching is done on the IANA cipher suite ID and the integer TLS
//! version, not on AWS-LC's textual cipher names. The string-based
//! match path is reserved for diagnostic output in
//! [`crate::KtlsEligibility`] and in `IneligibleCipher` errors.

use std::os::raw::c_int;

use crate::ffi::Ssl;

/// One of the six (version, AEAD) combinations the Linux kernel `tls`
/// ULP can offload, as established by AWS-LC at the end of the handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KtlsCipher {
    Tls13Aes128Gcm,
    Tls13Aes256Gcm,
    Tls13Chacha20Poly1305,
    Tls12Aes128Gcm,
    Tls12Aes256Gcm,
    Tls12Chacha20Poly1305,
}

impl KtlsCipher {
    /// Inspect a finished SSL handshake. Returns `Some` iff the
    /// negotiated `(version, cipher)` pair is structurally eligible
    /// for kTLS offload.
    pub(crate) fn detect(ssl: &Ssl) -> Option<Self> {
        // SAFETY: ssl is live; SSL_version is a pure read returning the
        // TLSx_VERSION integer constant.
        let version = unsafe { aws_lc_sys::SSL_version(ssl.as_ptr()) };
        // SAFETY: ssl is live; SSL_get_current_cipher returns a borrowed
        // SSL_CIPHER pointer or null when no cipher has been negotiated.
        let cipher = unsafe { aws_lc_sys::SSL_get_current_cipher(ssl.as_ptr()) };
        if cipher.is_null() {
            return None;
        }
        // SAFETY: cipher is live; SSL_CIPHER_get_protocol_id returns the
        // bare 2-byte IANA cipher-suite ID.
        let id = unsafe { aws_lc_sys::SSL_CIPHER_get_protocol_id(cipher) };
        Self::from_ids(version, id)
    }

    /// Pure mapping from raw `(version, IANA cipher-suite ID)` to the
    /// typed variant. Split out so it can be unit-tested without an SSL.
    fn from_ids(tls_version: c_int, cipher_id: u16) -> Option<Self> {
        // IANA cipher suite IDs, RFC 8446 §B.4 (TLS 1.3) and RFC 5288 /
        // RFC 7905 (TLS 1.2 AEAD).
        const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
        const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
        const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;
        const ECDHE_ECDSA_AES128_GCM_SHA256: u16 = 0xC02B;
        const ECDHE_RSA_AES128_GCM_SHA256: u16 = 0xC02F;
        const ECDHE_ECDSA_AES256_GCM_SHA384: u16 = 0xC02C;
        const ECDHE_RSA_AES256_GCM_SHA384: u16 = 0xC030;
        const ECDHE_ECDSA_CHACHA20_POLY1305: u16 = 0xCCA9;
        const ECDHE_RSA_CHACHA20_POLY1305: u16 = 0xCCA8;

        if tls_version == aws_lc_sys::TLS1_3_VERSION {
            match cipher_id {
                TLS_AES_128_GCM_SHA256 => Some(Self::Tls13Aes128Gcm),
                TLS_AES_256_GCM_SHA384 => Some(Self::Tls13Aes256Gcm),
                TLS_CHACHA20_POLY1305_SHA256 => Some(Self::Tls13Chacha20Poly1305),
                _ => None,
            }
        } else if tls_version == aws_lc_sys::TLS1_2_VERSION {
            match cipher_id {
                ECDHE_ECDSA_AES128_GCM_SHA256 | ECDHE_RSA_AES128_GCM_SHA256 => {
                    Some(Self::Tls12Aes128Gcm)
                }
                ECDHE_ECDSA_AES256_GCM_SHA384 | ECDHE_RSA_AES256_GCM_SHA384 => {
                    Some(Self::Tls12Aes256Gcm)
                }
                ECDHE_ECDSA_CHACHA20_POLY1305 | ECDHE_RSA_CHACHA20_POLY1305 => {
                    Some(Self::Tls12Chacha20Poly1305)
                }
                _ => None,
            }
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls13_aead_suites_recognised() {
        assert_eq!(
            KtlsCipher::from_ids(aws_lc_sys::TLS1_3_VERSION, 0x1301),
            Some(KtlsCipher::Tls13Aes128Gcm)
        );
        assert_eq!(
            KtlsCipher::from_ids(aws_lc_sys::TLS1_3_VERSION, 0x1302),
            Some(KtlsCipher::Tls13Aes256Gcm)
        );
        assert_eq!(
            KtlsCipher::from_ids(aws_lc_sys::TLS1_3_VERSION, 0x1303),
            Some(KtlsCipher::Tls13Chacha20Poly1305)
        );
    }

    #[test]
    fn tls12_aead_suites_recognised() {
        for id in [0xC02Bu16, 0xC02F] {
            assert_eq!(
                KtlsCipher::from_ids(aws_lc_sys::TLS1_2_VERSION, id),
                Some(KtlsCipher::Tls12Aes128Gcm),
                "id 0x{id:04X}"
            );
        }
        for id in [0xC02Cu16, 0xC030] {
            assert_eq!(
                KtlsCipher::from_ids(aws_lc_sys::TLS1_2_VERSION, id),
                Some(KtlsCipher::Tls12Aes256Gcm),
                "id 0x{id:04X}"
            );
        }
        for id in [0xCCA8u16, 0xCCA9] {
            assert_eq!(
                KtlsCipher::from_ids(aws_lc_sys::TLS1_2_VERSION, id),
                Some(KtlsCipher::Tls12Chacha20Poly1305),
                "id 0x{id:04X}"
            );
        }
    }

    #[test]
    fn non_aead_tls12_rejected() {
        // ECDHE-RSA-AES128-CBC-SHA (0xC013), the canonical non-AEAD
        // ciphersuite still on the wire in TLS 1.2 corners.
        assert!(KtlsCipher::from_ids(aws_lc_sys::TLS1_2_VERSION, 0xC013).is_none());
    }

    #[test]
    fn tls13_with_tls12_cipher_rejected() {
        // TLS 1.2 IDs are not valid under a TLS 1.3 negotiation.
        assert!(KtlsCipher::from_ids(aws_lc_sys::TLS1_3_VERSION, 0xC02F).is_none());
    }

    #[test]
    fn pre_tls12_rejected() {
        // TLS 1.0 = 0x0301, TLS 1.1 = 0x0302; neither has kTLS support.
        assert!(KtlsCipher::from_ids(0x0301, 0x1301).is_none());
        assert!(KtlsCipher::from_ids(0x0302, 0xC02F).is_none());
    }
}
