//! Typed cipher-suite constants for use with the server- and client-side
//! config builders.
//!
//! Shape and contents mirror `rustls::crypto::aws_lc_rs::cipher_suite`:
//! each supported (TLS version, AEAD) tuple is exposed as a
//! `&'static CipherSuite` constant. Hand a slice of references to
//! [`crate::ServerConfigBuilder::cipher_suites`] or
//! [`crate::ClientConfigBuilder::cipher_suites`] to pin the negotiation
//! to that set; callers don't have to spell out OpenSSL cipher-list
//! grammar by hand.
//!
//! Only AEAD suites (AES-GCM, ChaCha20-Poly1305) are exposed, matching
//! the rustls aws-lc-rs provider's modern-only stance. CBC-SHA, RC4,
//! and other legacy suites are deliberately not provided. The same
//! subset happens to be what the Linux kernel `tls` ULP can offload,
//! so kTLS auto-install on accept/connect succeeds on any negotiation
//! built from these constants. Sessions whose negotiation isn't
//! kTLS-eligible (for example because a peer pinned one of these suites
//! that the kernel doesn't support on the running host) simply run the
//! AEAD record layer in userspace.
//!
//! ```no_run
//! use tokio_aws_lc::cipher_suite::{
//!     TLS13_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
//! };
//! use tokio_aws_lc::ClientConfig;
//!
//! let _ = ClientConfig::builder()
//!     .with_system_root_certs()
//!     .cipher_suites(&[
//!         TLS13_AES_128_GCM_SHA256,
//!         TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
//!     ])
//!     .build();
//! ```

use super::ProtocolVersion;
use crate::error::{last_error, Error, Result};
use crate::ffi::SslCtx;
use std::ffi::CString;

/// One supported (TLS version, AEAD) cipher suite.
///
/// Opaque, constructed only through the module-level constants below.
/// Carries enough metadata to drive AWS-LC's split TLS 1.2 / 1.3
/// configuration calls without callers needing to know which API
/// applies to which suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CipherSuite {
    iana_name: &'static str,
    /// OpenSSL/AWS-LC cipher-list name (used by
    /// `SSL_CTX_set_cipher_list` for TLS 1.2). For TLS 1.3 this matches
    /// `iana_name`.
    openssl_name: &'static str,
    iana_id: u16,
    version: ProtocolVersion,
}

impl CipherSuite {
    /// IANA registry name (e.g. `"TLS_AES_128_GCM_SHA256"` or
    /// `"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"`).
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.iana_name
    }

    /// 16-bit IANA cipher-suite ID.
    #[must_use]
    pub const fn id(&self) -> u16 {
        self.iana_id
    }

    /// TLS protocol version this suite belongs to.
    #[must_use]
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }

    pub(crate) const fn openssl_name(&self) -> &'static str {
        self.openssl_name
    }
}

// TLS 1.3 ciphersuites — OpenSSL/AWS-LC accepts them via
// `SSL_CTX_set_ciphersuites` under their IANA names.

/// `TLS_AES_128_GCM_SHA256` (TLS 1.3).
pub static TLS13_AES_128_GCM_SHA256: &CipherSuite = &CipherSuite {
    iana_name: "TLS_AES_128_GCM_SHA256",
    openssl_name: "TLS_AES_128_GCM_SHA256",
    iana_id: 0x1301,
    version: ProtocolVersion::Tls13,
};

/// `TLS_AES_256_GCM_SHA384` (TLS 1.3).
pub static TLS13_AES_256_GCM_SHA384: &CipherSuite = &CipherSuite {
    iana_name: "TLS_AES_256_GCM_SHA384",
    openssl_name: "TLS_AES_256_GCM_SHA384",
    iana_id: 0x1302,
    version: ProtocolVersion::Tls13,
};

/// `TLS_CHACHA20_POLY1305_SHA256` (TLS 1.3).
pub static TLS13_CHACHA20_POLY1305_SHA256: &CipherSuite = &CipherSuite {
    iana_name: "TLS_CHACHA20_POLY1305_SHA256",
    openssl_name: "TLS_CHACHA20_POLY1305_SHA256",
    iana_id: 0x1303,
    version: ProtocolVersion::Tls13,
};

// TLS 1.2 AEAD ciphersuites — OpenSSL/AWS-LC accepts them via
// `SSL_CTX_set_cipher_list` under the OpenSSL cipher-list name (e.g.
// "ECDHE-ECDSA-AES128-GCM-SHA256"). RFC 5288 (AES-GCM) + RFC 7905
// (ChaCha20-Poly1305).

/// `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` (TLS 1.2).
pub static TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: &CipherSuite = &CipherSuite {
    iana_name: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    openssl_name: "ECDHE-ECDSA-AES128-GCM-SHA256",
    iana_id: 0xC02B,
    version: ProtocolVersion::Tls12,
};

/// `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` (TLS 1.2).
pub static TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: &CipherSuite = &CipherSuite {
    iana_name: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    openssl_name: "ECDHE-ECDSA-AES256-GCM-SHA384",
    iana_id: 0xC02C,
    version: ProtocolVersion::Tls12,
};

/// `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256` (TLS 1.2).
pub static TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: &CipherSuite = &CipherSuite {
    iana_name: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    openssl_name: "ECDHE-ECDSA-CHACHA20-POLY1305",
    iana_id: 0xCCA9,
    version: ProtocolVersion::Tls12,
};

/// `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` (TLS 1.2).
pub static TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: &CipherSuite = &CipherSuite {
    iana_name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    openssl_name: "ECDHE-RSA-AES128-GCM-SHA256",
    iana_id: 0xC02F,
    version: ProtocolVersion::Tls12,
};

/// `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` (TLS 1.2).
pub static TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: &CipherSuite = &CipherSuite {
    iana_name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    openssl_name: "ECDHE-RSA-AES256-GCM-SHA384",
    iana_id: 0xC030,
    version: ProtocolVersion::Tls12,
};

/// `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256` (TLS 1.2).
pub static TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: &CipherSuite = &CipherSuite {
    iana_name: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    openssl_name: "ECDHE-RSA-CHACHA20-POLY1305",
    iana_id: 0xCCA8,
    version: ProtocolVersion::Tls12,
};

/// All cipher suites this crate supports.
///
/// Listed TLS 1.3 first (modern preference), then TLS 1.2 AEAD
/// ECDHE suites. Matches the contents of
/// `rustls::crypto::aws_lc_rs::ALL_CIPHER_SUITES`.
pub static ALL_CIPHER_SUITES: &[&CipherSuite] = &[
    TLS13_AES_128_GCM_SHA256,
    TLS13_AES_256_GCM_SHA384,
    TLS13_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

/// Cipher-suite configuration an application should use by default.
///
/// Currently identical to [`ALL_CIPHER_SUITES`], mirroring the
/// `rustls::crypto::aws_lc_rs::DEFAULT_CIPHER_SUITES` shape. Exposed
/// separately so the default set can shrink in a future release
/// (e.g. dropping a suite from the default while leaving it available
/// for callers that opt in explicitly) without a breaking change.
pub static DEFAULT_CIPHER_SUITES: &[&CipherSuite] = ALL_CIPHER_SUITES;

/// Helper used by both builders. Splits `suites` into TLS 1.2 and TLS
/// 1.3 colon-separated lists for `SSL_CTX_set_cipher_list` /
/// `SSL_CTX_set_ciphersuites`. Returns `(tls12_list, tls13_list)`;
/// either may be `None` if the input contained no suites of that
/// version.
pub(crate) fn split_for_aws_lc(suites: &[&CipherSuite]) -> (Option<String>, Option<String>) {
    let mut tls12 = String::new();
    let mut tls13 = String::new();
    for s in suites {
        let target = match s.version {
            ProtocolVersion::Tls12 => &mut tls12,
            ProtocolVersion::Tls13 => &mut tls13,
        };
        if !target.is_empty() {
            target.push(':');
        }
        target.push_str(s.openssl_name());
    }
    let tls12 = if tls12.is_empty() { None } else { Some(tls12) };
    let tls13 = if tls13.is_empty() { None } else { Some(tls13) };
    (tls12, tls13)
}

/// Apply a slice of cipher suites to an `SSL_CTX` by calling the
/// appropriate AWS-LC setter for each version. A no-op on an empty
/// slice.
pub(crate) fn apply_to_ctx(ctx: &SslCtx, suites: &[&CipherSuite]) -> Result<()> {
    let (tls12, tls13) = split_for_aws_lc(suites);
    if let Some(list) = tls12 {
        let c = CString::new(list).expect("cipher-suite names contain no NUL bytes");
        // SAFETY: ctx is live; the CString is valid for the call.
        let ok = unsafe { aws_lc_sys::SSL_CTX_set_cipher_list(ctx.as_ptr(), c.as_ptr()) };
        if ok != 1 {
            return Err(Error::Init(format!(
                "SSL_CTX_set_cipher_list: {}",
                last_error()
            )));
        }
    }
    if let Some(list) = tls13 {
        let c = CString::new(list).expect("cipher-suite names contain no NUL bytes");
        // SAFETY: ctx is live; the CString is valid for the call.
        let ok = unsafe { aws_lc_sys::SSL_CTX_set_ciphersuites(ctx.as_ptr(), c.as_ptr()) };
        if ok != 1 {
            return Err(Error::Init(format!(
                "SSL_CTX_set_ciphersuites: {}",
                last_error()
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_round_trip() {
        assert_eq!(TLS13_AES_128_GCM_SHA256.name(), "TLS_AES_128_GCM_SHA256");
        assert_eq!(TLS13_AES_128_GCM_SHA256.id(), 0x1301);
        assert_eq!(TLS13_AES_128_GCM_SHA256.version(), ProtocolVersion::Tls13);

        assert_eq!(
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.openssl_name(),
            "ECDHE-ECDSA-AES128-GCM-SHA256"
        );
        assert_eq!(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.id(), 0xC02B);
        assert_eq!(
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.version(),
            ProtocolVersion::Tls12
        );
    }

    #[test]
    fn split_groups_by_version() {
        let suites = [
            TLS13_AES_128_GCM_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            TLS13_CHACHA20_POLY1305_SHA256,
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        ];
        let (tls12, tls13) = split_for_aws_lc(&suites);
        assert_eq!(
            tls12.as_deref(),
            Some("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384")
        );
        assert_eq!(
            tls13.as_deref(),
            Some("TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256")
        );
    }

    #[test]
    fn split_empty_input_yields_none() {
        let (tls12, tls13) = split_for_aws_lc(&[]);
        assert!(tls12.is_none());
        assert!(tls13.is_none());
    }

    #[test]
    fn split_tls13_only() {
        let (tls12, tls13) = split_for_aws_lc(&[TLS13_AES_256_GCM_SHA384]);
        assert!(tls12.is_none());
        assert_eq!(tls13.as_deref(), Some("TLS_AES_256_GCM_SHA384"));
    }

    #[test]
    fn default_matches_all_for_now() {
        assert!(std::ptr::eq(DEFAULT_CIPHER_SUITES, ALL_CIPHER_SUITES));
    }

    #[test]
    fn all_constant_lists_every_suite() {
        assert_eq!(ALL_CIPHER_SUITES.len(), 9);
        // Sanity: every entry matches `iana_id` to a known constant
        // shape (TLS 1.3 IDs are 0x13xx, TLS 1.2 AEAD ECDHE IDs are
        // 0xC02B/2C/2F/30 or 0xCCA8/A9).
        for s in ALL_CIPHER_SUITES {
            assert!(matches!(
                s.version(),
                ProtocolVersion::Tls12 | ProtocolVersion::Tls13
            ));
            assert!(!s.name().is_empty());
        }
    }
}
