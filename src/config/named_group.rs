//! Named-group (key-exchange) selection for both server and client.
//!
//! TLS 1.3 calls them "supported groups" (RFC 8446 §4.2.7); TLS 1.2
//! calls the same registry "named curves" (RFC 8422). AWS-LC's
//! [`SSL_CTX_set1_groups`] takes an array of NIDs and consults the
//! result during ECDHE / hybrid PQ negotiation.
//!
//! The default group list AWS-LC ships includes the hybrid
//! post-quantum group `X25519MLKEM768`, which is significantly more
//! expensive than classical X25519. That's the right default for
//! production — it provides forward secrecy against a future
//! quantum-capable adversary recording today's handshake — but if you
//! need to opt out for latency or interoperability reasons, configure
//! an explicit group list via
//! [`crate::ServerConfigBuilder::named_groups`] /
//! [`crate::ClientConfigBuilder::named_groups`].
//!
//! [`SSL_CTX_set1_groups`]: https://www.openssl.org/docs/man3.0/man3/SSL_CTX_set1_groups.html

use std::os::raw::c_int;

use crate::error::{last_error, Error, Result};
use crate::ffi::SslCtx;

/// A TLS named group usable for key exchange. Variants cover every
/// group AWS-LC currently negotiates; new variants may be added in a
/// minor release as AWS-LC gains support, hence `#[non_exhaustive]`.
///
/// The variant list intentionally mirrors the names AWS-LC and the
/// IANA registry use, so cross-referencing wire captures and other
/// TLS stacks is straightforward.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NamedGroup {
    /// X25519 elliptic-curve Diffie–Hellman (RFC 7748). Classical
    /// curve, fastest of the lot, and the universal default across
    /// modern TLS implementations.
    X25519,
    /// NIST P-256 / secp256r1.
    Secp256r1,
    /// NIST P-384 / secp384r1.
    Secp384r1,
    /// NIST P-521 / secp521r1.
    Secp521r1,
    /// Hybrid post-quantum: X25519 + ML-KEM-768
    /// (`draft-ietf-tls-hybrid-design`, IANA code `0x11ec`).
    /// AWS-LC's default first preference.
    X25519MLKEM768,
    /// Hybrid post-quantum: NIST P-256 + ML-KEM-768.
    SecP256r1MLKEM768,
    /// Hybrid post-quantum: NIST P-384 + ML-KEM-1024.
    SecP384r1MLKEM1024,
}

impl NamedGroup {
    /// The AWS-LC NID for this group, suitable for
    /// [`SSL_CTX_set1_groups`](aws_lc_sys::SSL_CTX_set1_groups).
    pub(crate) fn nid(self) -> c_int {
        match self {
            Self::X25519 => aws_lc_sys::NID_X25519,
            Self::Secp256r1 => aws_lc_sys::NID_X9_62_prime256v1,
            Self::Secp384r1 => aws_lc_sys::NID_secp384r1,
            Self::Secp521r1 => aws_lc_sys::NID_secp521r1,
            Self::X25519MLKEM768 => aws_lc_sys::NID_X25519MLKEM768,
            Self::SecP256r1MLKEM768 => aws_lc_sys::NID_SecP256r1MLKEM768,
            Self::SecP384r1MLKEM1024 => aws_lc_sys::NID_SecP384r1MLKEM1024,
        }
    }
}

/// Apply a non-empty named-group preference list to `ctx`. Order is
/// caller preference; AWS-LC honours it in `ClientHello` (client) or
/// when picking a key share (server).
pub(crate) fn apply_to_ctx(ctx: &SslCtx, groups: &[NamedGroup]) -> Result<()> {
    debug_assert!(!groups.is_empty(), "caller must guard against empty list");
    let nids: Vec<c_int> = groups.iter().copied().map(NamedGroup::nid).collect();
    // SAFETY: ctx is live; nids is a contiguous c_int buffer of the
    // declared length, valid for the duration of the call.
    let ok = unsafe { aws_lc_sys::SSL_CTX_set1_groups(ctx.as_ptr(), nids.as_ptr(), nids.len()) };
    if ok != 1 {
        return Err(Error::Init(format!(
            "SSL_CTX_set1_groups: {}",
            last_error()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nids_match_bindings() {
        // Sanity that the table doesn't drift from the AWS-LC headers.
        assert_eq!(NamedGroup::X25519.nid(), aws_lc_sys::NID_X25519);
        assert_eq!(
            NamedGroup::Secp256r1.nid(),
            aws_lc_sys::NID_X9_62_prime256v1
        );
        assert_eq!(NamedGroup::Secp384r1.nid(), aws_lc_sys::NID_secp384r1);
        assert_eq!(NamedGroup::Secp521r1.nid(), aws_lc_sys::NID_secp521r1);
        assert_eq!(
            NamedGroup::X25519MLKEM768.nid(),
            aws_lc_sys::NID_X25519MLKEM768
        );
        assert_eq!(
            NamedGroup::SecP256r1MLKEM768.nid(),
            aws_lc_sys::NID_SecP256r1MLKEM768
        );
        assert_eq!(
            NamedGroup::SecP384r1MLKEM1024.nid(),
            aws_lc_sys::NID_SecP384r1MLKEM1024
        );
    }

    #[test]
    fn apply_to_ctx_accepts_known_groups() {
        // SAFETY: TLS_client_method is static; SslCtx::from_raw takes ownership.
        let raw = unsafe { aws_lc_sys::SSL_CTX_new(aws_lc_sys::TLS_client_method()) };
        let ctx = unsafe { SslCtx::from_raw(raw) }.expect("SSL_CTX_new");
        apply_to_ctx(
            &ctx,
            &[
                NamedGroup::X25519,
                NamedGroup::Secp256r1,
                NamedGroup::X25519MLKEM768,
            ],
        )
        .expect("apply_to_ctx accepts a mixed classical/PQ list");
    }
}
