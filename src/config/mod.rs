//! Configuration types shared between server and client builders.

pub mod cipher_suite;
mod client;
mod der;
mod named_group;
mod server;

pub use cipher_suite::CipherSuite;
pub use client::{ClientConfig, ClientConfigBuilder};
pub use named_group::NamedGroup;
pub use server::{ClientAuthMode, ServerConfig, ServerConfigBuilder};

/// TLS protocol version selector used by the min/max version setters on
/// both [`ServerConfigBuilder`] and (later) `ClientConfigBuilder`.
///
/// Only versions this crate actively supports are listed. Older versions
/// (`SSLv3`, TLS 1.0, TLS 1.1) are not exposed; AWS-LC has removed or
/// disabled them and we do not re-enable them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ProtocolVersion {
    /// TLS 1.2.
    Tls12,
    /// TLS 1.3.
    Tls13,
}

impl ProtocolVersion {
    /// The AWS-LC `TLS*_VERSION` constant matching this variant, as the
    /// `u16` accepted by `SSL_CTX_set_{min,max}_proto_version`.
    pub(crate) fn raw(self) -> u16 {
        let v = match self {
            Self::Tls12 => aws_lc_sys::TLS1_2_VERSION,
            Self::Tls13 => aws_lc_sys::TLS1_3_VERSION,
        };
        u16::try_from(v).expect("AWS-LC TLS*_VERSION constants fit in u16")
    }
}

/// Iterate AWS-LC's wire-format ALPN protocol list (`<len><bytes>...`).
///
/// Yields each inner protocol slice. Stops on the first malformed entry
/// (truncated length prefix); the rest is silently dropped.
pub(crate) fn iter_alpn_wire(mut buf: &[u8]) -> impl Iterator<Item = &[u8]> {
    std::iter::from_fn(move || {
        if buf.is_empty() {
            return None;
        }
        let len = buf[0] as usize;
        if buf.len() < 1 + len {
            return None;
        }
        let (proto, rest) = buf[1..].split_at(len);
        buf = rest;
        Some(proto)
    })
}

/// Encode a list of ALPN protocols into AWS-LC's wire format
/// (`<len><bytes>` repeated). Returns `Err` if any protocol is empty or
/// longer than 255 bytes — both are spec violations.
pub(crate) fn encode_alpn_wire(protos: &[&[u8]]) -> Result<Vec<u8>, AlpnEncodeError> {
    let mut out = Vec::with_capacity(protos.iter().map(|p| p.len() + 1).sum());
    for p in protos {
        if p.is_empty() {
            return Err(AlpnEncodeError::Empty);
        }
        let len: u8 = p.len().try_into().map_err(|_| AlpnEncodeError::TooLong)?;
        out.push(len);
        out.extend_from_slice(p);
    }
    Ok(out)
}

#[derive(Debug)]
pub(crate) enum AlpnEncodeError {
    Empty,
    TooLong,
}

impl std::fmt::Display for AlpnEncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => f.write_str("ALPN protocol identifier must be non-empty"),
            Self::TooLong => f.write_str("ALPN protocol identifier exceeds 255 bytes"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_wire_round_trip() {
        let encoded = encode_alpn_wire(&[b"h2", b"http/1.1"]).unwrap();
        assert_eq!(encoded, b"\x02h2\x08http/1.1");
        let decoded: Vec<&[u8]> = iter_alpn_wire(&encoded).collect();
        assert_eq!(decoded, vec![b"h2".as_slice(), b"http/1.1"]);
    }

    #[test]
    fn alpn_wire_empty_proto_rejected() {
        assert!(matches!(
            encode_alpn_wire(&[b""]),
            Err(AlpnEncodeError::Empty)
        ));
    }

    #[test]
    fn alpn_wire_too_long_rejected() {
        let too_long = vec![b'x'; 256];
        let bad: &[&[u8]] = &[&too_long];
        assert!(matches!(
            encode_alpn_wire(bad),
            Err(AlpnEncodeError::TooLong)
        ));
    }

    #[test]
    fn alpn_encode_error_display() {
        assert_eq!(
            AlpnEncodeError::Empty.to_string(),
            "ALPN protocol identifier must be non-empty"
        );
        assert_eq!(
            AlpnEncodeError::TooLong.to_string(),
            "ALPN protocol identifier exceeds 255 bytes"
        );
    }

    #[test]
    fn alpn_wire_truncated_is_silently_dropped() {
        // Length prefix says 5, only 2 bytes follow.
        let bad = b"\x05ab";
        let decoded: Vec<&[u8]> = iter_alpn_wire(bad).collect();
        assert!(decoded.is_empty());
    }

    #[test]
    fn protocol_version_raw_matches_bindings() {
        assert_eq!(
            i32::from(ProtocolVersion::Tls12.raw()),
            aws_lc_sys::TLS1_2_VERSION
        );
        assert_eq!(
            i32::from(ProtocolVersion::Tls13.raw()),
            aws_lc_sys::TLS1_3_VERSION
        );
    }
}
