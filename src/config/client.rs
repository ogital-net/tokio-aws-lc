//! Client-side TLS configuration.
//!
//! [`ClientConfig`] wraps an `SSL_CTX` configured for the connect side.
//! Verification is on by default (`SSL_VERIFY_PEER`); turning it off
//! requires an explicit setter so the danger is visible at the call site.

use std::os::raw::c_int;
use std::ptr;

use crate::error::{last_error, pem_eof_or_err, Error, Result};
use crate::ffi::SslCtx;

use super::cipher_suite::{self, CipherSuite};
use super::named_group::{self, NamedGroup};
use super::{encode_alpn_wire, ProtocolVersion};

/// A built, immutable client-side TLS configuration. Cheap to clone via
/// `Arc`; share across many [`crate::TlsConnector`]s.
pub struct ClientConfig {
    pub(crate) ctx: SslCtx,
    pub(crate) ktls_disabled: bool,
}

// SAFETY: ClientConfig is logically immutable after construction. The
// underlying SSL_CTX is documented to be safe for concurrent read use
// (verification of new SSL handles only).
unsafe impl Send for ClientConfig {}
unsafe impl Sync for ClientConfig {}

impl ClientConfig {
    /// Start building a client configuration.
    #[must_use]
    pub fn builder() -> ClientConfigBuilder {
        ClientConfigBuilder::default()
    }

    /// Raw access to the underlying `SSL_CTX` pointer. Used by
    /// [`crate::TlsConnector`] when minting per-connection `SSL` handles.
    pub(crate) fn ctx_ptr(&self) -> *mut aws_lc_sys::SSL_CTX {
        self.ctx.as_ptr()
    }
}

impl std::fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientConfig").finish_non_exhaustive()
    }
}

/// Trust-root source. Configured via [`ClientConfigBuilder::roots`].
#[derive(Debug, Default)]
enum Roots {
    /// Use the platform/system default verify paths.
    #[default]
    System,
    /// Use a custom PEM bundle.
    Pem(Vec<u8>),
    /// Use a custom DER bundle (each element is one DER-encoded
    /// certificate).
    Der(Vec<Vec<u8>>),
    /// Disable peer verification entirely. Test-only.
    Disabled,
}

/// Optional client certificate + private key for mTLS.
#[derive(Debug)]
enum ClientAuth {
    Pem {
        cert_pem: Vec<u8>,
        key_pem: Vec<u8>,
    },
    Der {
        cert_chain_der: Vec<Vec<u8>>,
        key_der: Vec<u8>,
    },
}

/// Builder for [`ClientConfig`].
#[derive(Debug, Default)]
pub struct ClientConfigBuilder {
    roots: Roots,
    alpn_protocols: Vec<Vec<u8>>,
    min_version: Option<ProtocolVersion>,
    max_version: Option<ProtocolVersion>,
    client_auth: Option<ClientAuth>,
    cipher_suites: Option<Vec<&'static CipherSuite>>,
    named_groups: Option<Vec<NamedGroup>>,
    ktls_disabled: bool,
}

impl ClientConfigBuilder {
    /// Use the system default verify paths (the AWS-LC equivalent of
    /// OpenSSL's `SSL_CTX_set_default_verify_paths`). This is the default
    /// if no other trust-root source is configured.
    #[must_use]
    pub fn with_system_root_certs(mut self) -> Self {
        self.roots = Roots::System;
        self
    }

    /// Use a custom PEM bundle as the only trust anchors.
    #[must_use]
    pub fn with_root_certs_pem_bytes(mut self, pem: &[u8]) -> Self {
        self.roots = Roots::Pem(pem.to_vec());
        self
    }

    /// Use a list of DER-encoded certificates as the only trust
    /// anchors. Each element of `certs` is one DER `Certificate`
    /// body. Avoids the PEM round-trip when integrating with tooling
    /// that already emits DER (HSM exports, ASN.1 generators).
    #[must_use]
    pub fn with_root_certs_der_bytes(mut self, certs: &[&[u8]]) -> Self {
        self.roots = Roots::Der(certs.iter().map(|c| c.to_vec()).collect());
        self
    }

    /// Disable peer verification entirely. **Test-only**: every name
    /// resolves to the moon, every CA is trusted, every man-in-the-middle
    /// succeeds. Don't ship this on by default.
    #[must_use]
    pub fn dangerous_disable_verification(mut self) -> Self {
        self.roots = Roots::Disabled;
        self
    }

    /// Offer this list of ALPN protocols in the `ClientHello`. Order is
    /// client preference; the server picks one.
    #[must_use]
    pub fn alpn_protocols(mut self, protos: &[&[u8]]) -> Self {
        self.alpn_protocols = protos.iter().map(|p| p.to_vec()).collect();
        self
    }

    /// Minimum acceptable TLS version. Defaults to TLS 1.2.
    #[must_use]
    pub fn min_protocol_version(mut self, v: ProtocolVersion) -> Self {
        self.min_version = Some(v);
        self
    }

    /// Maximum acceptable TLS version. Defaults to TLS 1.3.
    #[must_use]
    pub fn max_protocol_version(mut self, v: ProtocolVersion) -> Self {
        self.max_version = Some(v);
        self
    }

    /// Present the given certificate chain and private key during the
    /// handshake when the server requests a client certificate (mTLS).
    /// Both inputs are PEM-encoded byte slices.
    #[must_use]
    pub fn with_client_auth_pem_bytes(mut self, cert: &[u8], key: &[u8]) -> Self {
        self.client_auth = Some(ClientAuth::Pem {
            cert_pem: cert.to_vec(),
            key_pem: key.to_vec(),
        });
        self
    }

    /// Present the given certificate chain and private key during the
    /// handshake when the server requests a client certificate (mTLS).
    /// `cert_chain` is a slice of DER-encoded `Certificate` bodies in
    /// chain order (leaf first); `key` is a DER-encoded private key in
    /// PKCS#8, PKCS#1, or SEC1 format.
    #[must_use]
    pub fn with_client_auth_der_bytes(mut self, cert_chain: &[&[u8]], key: &[u8]) -> Self {
        self.client_auth = Some(ClientAuth::Der {
            cert_chain_der: cert_chain.iter().map(|c| c.to_vec()).collect(),
            key_der: key.to_vec(),
        });
        self
    }

    /// Restrict the offered cipher suites to the given set, using the
    /// typed constants in [`crate::cipher_suite`]. TLS 1.2 and TLS 1.3
    /// suites are accepted in the same slice; the builder routes each to
    /// the appropriate AWS-LC API.
    ///
    /// An empty slice clears any cipher-suite override and falls back
    /// to AWS-LC's defaults.
    #[must_use]
    pub fn cipher_suites(mut self, suites: &[&'static CipherSuite]) -> Self {
        self.cipher_suites = if suites.is_empty() {
            None
        } else {
            Some(suites.to_vec())
        };
        self
    }

    /// Restrict the offered key-exchange groups to the given list, in
    /// caller-preference order. Sent in the `ClientHello`'s
    /// `supported_groups` extension; the server picks one.
    ///
    /// AWS-LC's default group list leads with the hybrid post-quantum
    /// group [`NamedGroup::X25519MLKEM768`], which is significantly
    /// more expensive than classical X25519. Override this when you
    /// have a concrete latency or interoperability requirement; the
    /// default is the right call for general production traffic.
    ///
    /// An empty slice clears any override and falls back to AWS-LC's
    /// defaults.
    #[must_use]
    pub fn named_groups(mut self, groups: &[NamedGroup]) -> Self {
        self.named_groups = if groups.is_empty() {
            None
        } else {
            Some(groups.to_vec())
        };
        self
    }

    /// Disable kTLS for streams produced by this config.
    ///
    /// By default, [`crate::TlsConnector::connect`] attempts to install
    /// the Linux kernel `tls` ULP automatically once the handshake
    /// finishes, falling back silently to userspace AEAD when the host
    /// kernel does not support it. Calling this disables that attempt
    /// outright; see [`crate::ServerConfigBuilder::disable_ktls`] for
    /// the rationale.
    #[must_use]
    pub fn disable_ktls(mut self) -> Self {
        self.ktls_disabled = true;
        self
    }

    /// Finalise the configuration.
    #[allow(clippy::too_many_lines)]
    pub fn build(self) -> Result<ClientConfig> {
        let ctx = new_client_ctx()?;

        // Trust roots.
        match &self.roots {
            Roots::System => {
                // SAFETY: ctx is live.
                let ok = unsafe { aws_lc_sys::SSL_CTX_set_default_verify_paths(ctx.as_ptr()) };
                if ok != 1 {
                    return Err(Error::Init(format!(
                        "SSL_CTX_set_default_verify_paths: {}",
                        last_error()
                    )));
                }
                // SAFETY: ctx is live; SSL_VERIFY_PEER is a scalar.
                unsafe {
                    aws_lc_sys::SSL_CTX_set_verify(
                        ctx.as_ptr(),
                        aws_lc_sys::SSL_VERIFY_PEER as c_int,
                        None,
                    );
                }
            }
            Roots::Pem(pem) => {
                load_trust_anchors_pem(&ctx, pem)?;
                // SAFETY: ctx is live.
                unsafe {
                    aws_lc_sys::SSL_CTX_set_verify(
                        ctx.as_ptr(),
                        aws_lc_sys::SSL_VERIFY_PEER as c_int,
                        None,
                    );
                }
            }
            Roots::Der(certs) => {
                load_trust_anchors_der(&ctx, certs)?;
                // SAFETY: ctx is live.
                unsafe {
                    aws_lc_sys::SSL_CTX_set_verify(
                        ctx.as_ptr(),
                        aws_lc_sys::SSL_VERIFY_PEER as c_int,
                        None,
                    );
                }
            }
            Roots::Disabled => {
                // SAFETY: ctx is live.
                unsafe {
                    aws_lc_sys::SSL_CTX_set_verify(
                        ctx.as_ptr(),
                        aws_lc_sys::SSL_VERIFY_NONE as c_int,
                        None,
                    );
                }
            }
        }

        // Optional mTLS material.
        if let Some(auth) = &self.client_auth {
            match auth {
                ClientAuth::Pem { cert_pem, key_pem } => {
                    load_client_cert_chain_pem(&ctx, cert_pem)?;
                    load_client_private_key_pem(&ctx, key_pem)?;
                }
                ClientAuth::Der {
                    cert_chain_der,
                    key_der,
                } => {
                    let chain_refs: Vec<&[u8]> = cert_chain_der.iter().map(Vec::as_slice).collect();
                    load_client_cert_chain_der(&ctx, &chain_refs)?;
                    load_client_private_key_der(&ctx, key_der)?;
                }
            }
            // SAFETY: ctx is live.
            let ok = unsafe { aws_lc_sys::SSL_CTX_check_private_key(ctx.as_ptr()) };
            if ok != 1 {
                return Err(Error::Init(format!(
                    "client cert and private key do not match: {}",
                    last_error()
                )));
            }
        }

        // Version bounds.
        let min_v = self.min_version.unwrap_or(ProtocolVersion::Tls12).raw();
        let max_v = self.max_version.unwrap_or(ProtocolVersion::Tls13).raw();
        // SAFETY: ctx is live.
        unsafe {
            if aws_lc_sys::SSL_CTX_set_min_proto_version(ctx.as_ptr(), min_v) != 1 {
                return Err(Error::Init(format!(
                    "SSL_CTX_set_min_proto_version: {}",
                    last_error()
                )));
            }
            if aws_lc_sys::SSL_CTX_set_max_proto_version(ctx.as_ptr(), max_v) != 1 {
                return Err(Error::Init(format!(
                    "SSL_CTX_set_max_proto_version: {}",
                    last_error()
                )));
            }
        }

        // User-supplied cipher-suite override.
        if let Some(suites) = &self.cipher_suites {
            cipher_suite::apply_to_ctx(&ctx, suites)?;
        }

        // User-supplied named-group preference list (key exchange).
        if let Some(groups) = &self.named_groups {
            named_group::apply_to_ctx(&ctx, groups)?;
        }

        // ALPN: client-side just hands over the wire-encoded list. AWS-LC
        // copies the buffer internally, so the local Vec can be dropped
        // at the end of this scope.
        if !self.alpn_protocols.is_empty() {
            let refs: Vec<&[u8]> = self.alpn_protocols.iter().map(Vec::as_slice).collect();
            let wire = encode_alpn_wire(&refs)
                .map_err(|e| Error::Init(format!("encoding ALPN protocol list: {e}")))?;
            // SAFETY: ctx is live; wire is non-empty.
            let ok = unsafe {
                aws_lc_sys::SSL_CTX_set_alpn_protos(ctx.as_ptr(), wire.as_ptr(), wire.len())
            };
            // SSL_CTX_set_alpn_protos returns 0 on success (legacy OpenSSL
            // ABI quirk inherited by AWS-LC).
            if ok != 0 {
                return Err(Error::Init(format!(
                    "SSL_CTX_set_alpn_protos: {}",
                    last_error()
                )));
            }
        }

        Ok(ClientConfig {
            ctx,
            ktls_disabled: self.ktls_disabled,
        })
    }
}

fn new_client_ctx() -> Result<SslCtx> {
    // SAFETY: TLS_client_method returns a static SSL_METHOD pointer;
    // SSL_CTX_new returns either an owned pointer or null on failure.
    let raw = unsafe { aws_lc_sys::SSL_CTX_new(aws_lc_sys::TLS_client_method()) };
    // SAFETY: `raw` is the freshly-owned SSL_CTX (or null).
    unsafe { SslCtx::from_raw(raw) }
        .ok_or_else(|| Error::Init(format!("SSL_CTX_new: {}", last_error())))
}

/// Load every PEM certificate in `pem` into the `SSL_CTX`'s trust store.
fn load_trust_anchors_pem(ctx: &SslCtx, pem: &[u8]) -> Result<()> {
    // SAFETY: read-only BIO over a borrowed buffer.
    #[allow(clippy::cast_possible_wrap)]
    let bio = unsafe { aws_lc_sys::BIO_new_mem_buf(pem.as_ptr().cast(), pem.len() as isize) };
    if bio.is_null() {
        return Err(Error::Init(format!(
            "BIO_new_mem_buf for trust anchors: {}",
            last_error()
        )));
    }
    let bio = BioGuard(bio);

    // SAFETY: ctx is live; SSL_CTX_get_cert_store returns a borrowed
    // X509_STORE pointer owned by the context.
    let store = unsafe { aws_lc_sys::SSL_CTX_get_cert_store(ctx.as_ptr()) };
    if store.is_null() {
        return Err(Error::Init("SSL_CTX_get_cert_store returned null".into()));
    }

    let mut added = 0usize;
    loop {
        // SAFETY: bio is live; the null trio means no password callback.
        let cert =
            unsafe { aws_lc_sys::PEM_read_bio_X509(bio.0, ptr::null_mut(), None, ptr::null_mut()) };
        if cert.is_null() {
            pem_eof_or_err("PEM_read_bio_X509 (trust anchors)")?;
            break;
        }
        // SAFETY: store and cert are live; X509_STORE_add_cert bumps the
        // X509 refcount internally.
        let ok = unsafe { aws_lc_sys::X509_STORE_add_cert(store, cert) };
        // SAFETY: we own the local refcount regardless.
        unsafe { aws_lc_sys::X509_free(cert) };
        if ok != 1 {
            return Err(Error::Init(format!(
                "X509_STORE_add_cert: {}",
                last_error()
            )));
        }
        added += 1;
    }

    if added == 0 {
        return Err(Error::Init(
            "no certificates found in supplied trust-anchor PEM".into(),
        ));
    }
    Ok(())
}

fn load_client_cert_chain_pem(ctx: &SslCtx, pem: &[u8]) -> Result<()> {
    // SAFETY: read-only BIO over a borrowed buffer.
    #[allow(clippy::cast_possible_wrap)]
    let bio = unsafe { aws_lc_sys::BIO_new_mem_buf(pem.as_ptr().cast(), pem.len() as isize) };
    if bio.is_null() {
        return Err(Error::Init(format!(
            "BIO_new_mem_buf for client cert chain: {}",
            last_error()
        )));
    }
    let bio = BioGuard(bio);

    // SAFETY: bio is live; null trio = no password callback.
    let leaf =
        unsafe { aws_lc_sys::PEM_read_bio_X509_AUX(bio.0, ptr::null_mut(), None, ptr::null_mut()) };
    if leaf.is_null() {
        return Err(Error::Init(format!(
            "PEM_read_bio_X509_AUX (client leaf): {}",
            last_error()
        )));
    }
    // SAFETY: ctx and leaf are live; SSL_CTX_use_certificate bumps the ref.
    let ok = unsafe { aws_lc_sys::SSL_CTX_use_certificate(ctx.as_ptr(), leaf) };
    // SAFETY: we own a local ref.
    unsafe { aws_lc_sys::X509_free(leaf) };
    if ok != 1 {
        return Err(Error::Init(format!(
            "SSL_CTX_use_certificate (client): {}",
            last_error()
        )));
    }

    // SAFETY: ctx is live.
    unsafe {
        aws_lc_sys::SSL_CTX_clear_chain_certs(ctx.as_ptr());
    }

    loop {
        // SAFETY: bio is live.
        let extra =
            unsafe { aws_lc_sys::PEM_read_bio_X509(bio.0, ptr::null_mut(), None, ptr::null_mut()) };
        if extra.is_null() {
            pem_eof_or_err("PEM_read_bio_X509 (client chain)")?;
            break;
        }
        // SAFETY: ctx and extra are live; SSL_CTX_add0_chain_cert takes
        // ownership on success.
        let ok = unsafe { aws_lc_sys::SSL_CTX_add0_chain_cert(ctx.as_ptr(), extra) };
        if ok != 1 {
            // SAFETY: we still own on failure.
            unsafe { aws_lc_sys::X509_free(extra) };
            return Err(Error::Init(format!(
                "SSL_CTX_add0_chain_cert (client): {}",
                last_error()
            )));
        }
    }
    Ok(())
}

fn load_client_private_key_pem(ctx: &SslCtx, pem: &[u8]) -> Result<()> {
    // SAFETY: read-only BIO over a borrowed buffer.
    #[allow(clippy::cast_possible_wrap)]
    let bio = unsafe { aws_lc_sys::BIO_new_mem_buf(pem.as_ptr().cast(), pem.len() as isize) };
    if bio.is_null() {
        return Err(Error::Init(format!(
            "BIO_new_mem_buf for client private key: {}",
            last_error()
        )));
    }
    let bio = BioGuard(bio);

    // SAFETY: bio is live; null trio = no password callback.
    let key = unsafe {
        aws_lc_sys::PEM_read_bio_PrivateKey(bio.0, ptr::null_mut(), None, ptr::null_mut())
    };
    if key.is_null() {
        return Err(Error::Init(format!(
            "PEM_read_bio_PrivateKey (client): {}",
            last_error()
        )));
    }
    // SAFETY: ctx and key are live; SSL_CTX_use_PrivateKey bumps the ref.
    let ok = unsafe { aws_lc_sys::SSL_CTX_use_PrivateKey(ctx.as_ptr(), key) };
    // SAFETY: we own a local ref.
    unsafe { aws_lc_sys::EVP_PKEY_free(key) };
    if ok != 1 {
        return Err(Error::Init(format!(
            "SSL_CTX_use_PrivateKey (client): {}",
            last_error()
        )));
    }
    Ok(())
}

/// Install each DER-encoded certificate in `certs` as a trust anchor in
/// the `SSL_CTX`'s `X509_STORE`.
fn load_trust_anchors_der(ctx: &SslCtx, certs: &[Vec<u8>]) -> Result<()> {
    if certs.is_empty() {
        return Err(Error::Init(
            "DER trust-anchor list must contain at least one certificate".into(),
        ));
    }
    // SAFETY: ctx is live; SSL_CTX_get_cert_store returns a borrowed
    // X509_STORE pointer owned by the context.
    let store = unsafe { aws_lc_sys::SSL_CTX_get_cert_store(ctx.as_ptr()) };
    if store.is_null() {
        return Err(Error::Init("SSL_CTX_get_cert_store returned null".into()));
    }

    for der in certs {
        let cert = super::der::parse_x509(der)?;
        // SAFETY: store and cert are live; X509_STORE_add_cert bumps the
        // X509 refcount internally.
        let ok = unsafe { aws_lc_sys::X509_STORE_add_cert(store, cert) };
        // SAFETY: we own the local refcount regardless.
        unsafe { aws_lc_sys::X509_free(cert) };
        if ok != 1 {
            return Err(Error::Init(format!(
                "X509_STORE_add_cert (DER): {}",
                last_error()
            )));
        }
    }
    Ok(())
}

fn load_client_cert_chain_der(ctx: &SslCtx, certs: &[&[u8]]) -> Result<()> {
    let (leaf_der, rest) = certs.split_first().ok_or_else(|| {
        Error::Init(
            "DER client certificate chain must contain at least the leaf certificate".into(),
        )
    })?;
    let leaf = super::der::parse_x509(leaf_der)?;
    // SAFETY: ctx and leaf are live; SSL_CTX_use_certificate bumps the ref.
    let ok = unsafe { aws_lc_sys::SSL_CTX_use_certificate(ctx.as_ptr(), leaf) };
    // SAFETY: we own a local ref.
    unsafe { aws_lc_sys::X509_free(leaf) };
    if ok != 1 {
        return Err(Error::Init(format!(
            "SSL_CTX_use_certificate (client DER leaf): {}",
            last_error()
        )));
    }
    // SAFETY: ctx is live.
    unsafe {
        aws_lc_sys::SSL_CTX_clear_chain_certs(ctx.as_ptr());
    }
    for extra_der in rest {
        let extra = super::der::parse_x509(extra_der)?;
        // SAFETY: ctx and extra are live; SSL_CTX_add0_chain_cert takes
        // ownership on success.
        let ok = unsafe { aws_lc_sys::SSL_CTX_add0_chain_cert(ctx.as_ptr(), extra) };
        if ok != 1 {
            // SAFETY: we still own on failure.
            unsafe { aws_lc_sys::X509_free(extra) };
            return Err(Error::Init(format!(
                "SSL_CTX_add0_chain_cert (client DER): {}",
                last_error()
            )));
        }
    }
    Ok(())
}

fn load_client_private_key_der(ctx: &SslCtx, der: &[u8]) -> Result<()> {
    let key = super::der::parse_private_key(der)?;
    // SAFETY: ctx and key are live; SSL_CTX_use_PrivateKey bumps the ref.
    let ok = unsafe { aws_lc_sys::SSL_CTX_use_PrivateKey(ctx.as_ptr(), key) };
    // SAFETY: we own a local ref.
    unsafe { aws_lc_sys::EVP_PKEY_free(key) };
    if ok != 1 {
        return Err(Error::Init(format!(
            "SSL_CTX_use_PrivateKey (client DER): {}",
            last_error()
        )));
    }
    Ok(())
}

struct BioGuard(*mut aws_lc_sys::BIO);
impl Drop for BioGuard {
    fn drop(&mut self) {
        // SAFETY: `self.0` was obtained from BIO_new_* and was not handed
        // off; we own the free.
        unsafe {
            aws_lc_sys::BIO_free(self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CERT_PEM: &[u8] = include_bytes!("../../tests/data/cert.pem");
    const TEST_KEY_PEM: &[u8] = include_bytes!("../../tests/data/key.pem");
    const TEST_CERT_DER: &[u8] = include_bytes!("../../tests/data/cert.der");
    const TEST_KEY_DER: &[u8] = include_bytes!("../../tests/data/key.der");

    #[test]
    fn builds_with_system_roots() {
        let cfg = ClientConfig::builder()
            .with_system_root_certs()
            .alpn_protocols(&[b"h2"])
            .build()
            .expect("system-root client config builds");
        assert!(!cfg.ctx_ptr().is_null());
    }

    #[test]
    fn builds_with_pem_roots() {
        let cfg = ClientConfig::builder()
            .with_root_certs_pem_bytes(TEST_CERT_PEM)
            .build()
            .expect("pem-root client config builds");
        assert!(!cfg.ctx_ptr().is_null());
    }

    #[test]
    fn builds_with_der_roots() {
        let cfg = ClientConfig::builder()
            .with_root_certs_der_bytes(&[TEST_CERT_DER])
            .build()
            .expect("der-root client config builds");
        assert!(!cfg.ctx_ptr().is_null());
    }

    #[test]
    fn empty_root_pem_rejected() {
        let err = ClientConfig::builder()
            .with_root_certs_pem_bytes(b"")
            .build()
            .expect_err("empty PEM should fail");
        assert!(matches!(err, Error::Init(_)), "got: {err:?}");
    }

    #[test]
    fn empty_root_der_list_rejected() {
        let err = ClientConfig::builder()
            .with_root_certs_der_bytes(&[])
            .build()
            .expect_err("empty DER list should fail");
        assert!(matches!(err, Error::Init(_)), "got: {err:?}");
    }

    #[test]
    fn builds_with_mtls_material() {
        let cfg = ClientConfig::builder()
            .with_root_certs_pem_bytes(TEST_CERT_PEM)
            .with_client_auth_pem_bytes(TEST_CERT_PEM, TEST_KEY_PEM)
            .build()
            .expect("mTLS client config builds");
        assert!(!cfg.ctx_ptr().is_null());
    }

    #[test]
    fn builds_with_mtls_der_material() {
        let cfg = ClientConfig::builder()
            .with_root_certs_der_bytes(&[TEST_CERT_DER])
            .with_client_auth_der_bytes(&[TEST_CERT_DER], TEST_KEY_DER)
            .build()
            .expect("DER mTLS client config builds");
        assert!(!cfg.ctx_ptr().is_null());
    }

    #[test]
    fn mtls_der_garbage_cert_rejected() {
        let err = ClientConfig::builder()
            .with_root_certs_der_bytes(&[TEST_CERT_DER])
            .with_client_auth_der_bytes(&[b"not a real DER cert"], TEST_KEY_DER)
            .build()
            .expect_err("garbage DER cert should fail");
        assert!(matches!(err, Error::Init(_)), "got: {err:?}");
    }
}
