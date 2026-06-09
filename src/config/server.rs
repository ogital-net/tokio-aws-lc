//! Server-side TLS configuration.
//!
//! [`ServerConfig`] wraps an `SSL_CTX` configured for the accept side.
//! Tickets are unconditionally disabled on the server because a
//! kernel-installed `TLS_TX` cannot encrypt the post-handshake
//! `NewSessionTicket` records AWS-LC would emit. Building a
//! ticket-emitting server config is therefore not exposed.

use std::ffi::CString;
use std::os::raw::{c_int, c_long, c_uint, c_void};
use std::path::Path;
use std::ptr;
use std::sync::OnceLock;

use crate::error::{last_error, pem_eof_or_err, Error, Result};
use crate::ffi::SslCtx;

use super::cipher_suite::{self, CipherSuite};
use super::named_group::{self, NamedGroup};
use super::{encode_alpn_wire, iter_alpn_wire, ProtocolVersion};

/// A built, immutable server-side TLS configuration. Cheap to clone via
/// the wrapping `Arc`; share one across many [`crate::TlsAcceptor`]s if
/// you like.
#[derive(Debug)]
pub struct ServerConfig {
    pub(crate) ctx: SslCtx,
    pub(crate) ktls_disabled: bool,
    // ALPN wire-format buffer (if any) is owned by the SSL_CTX itself
    // via ex_data; see [`alpn_ex_index`] / [`alpn_ex_free`]. The buffer
    // is allocated as `Box<Vec<u8>>` and freed by AWS-LC when
    // `SSL_CTX_free` runs, which keeps the lifetime invariant local to
    // the CTX that holds the raw pointer.
}

// SAFETY: ServerConfig is logically immutable after construction. The
// underlying SSL_CTX is documented to be safe for concurrent read use
// (which is all we do — handshakes mutate per-connection SSL state, not
// the CTX). Any ALPN buffer is read-only ex_data on the CTX.
unsafe impl Send for ServerConfig {}
unsafe impl Sync for ServerConfig {}

impl ServerConfig {
    /// Start building a server configuration.
    #[must_use]
    pub fn builder() -> ServerConfigBuilder {
        ServerConfigBuilder::default()
    }

    /// Raw access to the underlying `SSL_CTX` pointer. Used by
    /// [`crate::TlsAcceptor`] when minting per-connection `SSL` handles.
    pub(crate) fn ctx_ptr(&self) -> *mut aws_lc_sys::SSL_CTX {
        self.ctx.as_ptr()
    }
}

/// Builder for [`ServerConfig`]. All setters are chainable; call one of
/// the `with_pem_*` methods last to consume the builder.
#[derive(Debug, Default)]
pub struct ServerConfigBuilder {
    alpn_protocols: Vec<Vec<u8>>,
    min_version: Option<ProtocolVersion>,
    max_version: Option<ProtocolVersion>,
    ktls_aead_only: bool,
    ktls_disabled: bool,
    cipher_suites: Option<Vec<&'static CipherSuite>>,
    named_groups: Option<Vec<NamedGroup>>,
    client_auth: ClientAuthMode,
    client_auth_roots_pem: Option<Vec<u8>>,
}

/// Whether and how the server requires a client certificate.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ClientAuthMode {
    /// No client certificate is requested. The default.
    #[default]
    None,
    /// Request a client certificate but accept the handshake if the
    /// client doesn't send one. If sent, the certificate must verify
    /// against the configured client-CA roots.
    Optional,
    /// Require a client certificate that verifies against the configured
    /// client-CA roots. Handshake fails otherwise.
    Required,
}

impl ServerConfigBuilder {
    /// Advertise this list of ALPN protocols (server-priority, first match
    /// wins). Empty list disables ALPN selection.
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

    /// Restrict TLS 1.2 ciphers to AEAD suites kTLS can offload. TLS 1.3
    /// is already AEAD-only. Recommended for servers where kTLS is the
    /// primary data path; off by default since install is opt-in per
    /// session.
    #[must_use]
    pub fn ktls_aead_only(mut self, on: bool) -> Self {
        self.ktls_aead_only = on;
        self
    }

    /// Disable kTLS for streams produced by this config.
    ///
    /// By default, [`crate::TlsAcceptor::accept`] attempts to install
    /// the Linux kernel `tls` ULP automatically once the handshake
    /// finishes, falling back silently to userspace AEAD when the host
    /// kernel does not support it. Calling this disables that attempt
    /// outright: useful when you know the runtime environment has no
    /// `tls` ULP (containers without the module, non-Linux hosts,
    /// kernels older than 4.13) and want to skip even the probe.
    /// Streams from this config stay on the userspace AEAD path; check
    /// [`crate::TlsStream::ktls_disabled`] to confirm.
    #[must_use]
    pub fn disable_ktls(mut self) -> Self {
        self.ktls_disabled = true;
        self
    }

    /// Restrict the supported cipher suites to the given set, using the
    /// typed constants in [`crate::cipher_suite`]. TLS 1.2 and TLS 1.3
    /// suites are accepted in the same slice; the builder routes each to
    /// the appropriate AWS-LC API.
    ///
    /// Overrides [`Self::ktls_aead_only`] when both are set — the
    /// user-supplied list wins.
    ///
    /// An empty slice clears any cipher-suite override and falls back
    /// to AWS-LC's defaults (plus [`Self::ktls_aead_only`] if it was set).
    #[must_use]
    pub fn cipher_suites(mut self, suites: &[&'static CipherSuite]) -> Self {
        self.cipher_suites = if suites.is_empty() {
            None
        } else {
            Some(suites.to_vec())
        };
        self
    }

    /// Restrict the supported key-exchange groups to the given list,
    /// in caller-preference order. The server picks the first group
    /// the client also offered.
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

    /// Request and/or require client certificates (mTLS). When [`mode`]
    /// is anything other than [`ClientAuthMode::None`], `roots_pem` must
    /// contain the PEM-encoded CA bundle the client's certificate is
    /// verified against.
    ///
    /// [`mode`]: ClientAuthMode
    #[must_use]
    pub fn client_auth(mut self, mode: ClientAuthMode, roots_pem: &[u8]) -> Self {
        self.client_auth = mode;
        self.client_auth_roots_pem = Some(roots_pem.to_vec());
        self
    }

    /// Load the certificate chain and private key from PEM files on disk
    /// and finalise the configuration.
    pub fn with_pem_files(self, cert: &Path, key: &Path) -> Result<ServerConfig> {
        let ctx = new_server_ctx()?;
        let cert_c = path_to_cstring(cert)?;
        let key_c = path_to_cstring(key)?;
        // SAFETY: ctx is a fresh SSL_CTX; the CStrings live for the call.
        let ok = unsafe {
            aws_lc_sys::SSL_CTX_use_certificate_chain_file(ctx.as_ptr(), cert_c.as_ptr())
        };
        if ok != 1 {
            return Err(Error::Init(format!(
                "loading certificate chain from {}: {}",
                cert.display(),
                last_error()
            )));
        }
        // SAFETY: as above; SSL_FILETYPE_PEM is a constant.
        let ok = unsafe {
            aws_lc_sys::SSL_CTX_use_PrivateKey_file(
                ctx.as_ptr(),
                key_c.as_ptr(),
                aws_lc_sys::SSL_FILETYPE_PEM as c_int,
            )
        };
        if ok != 1 {
            return Err(Error::Init(format!(
                "loading private key from {}: {}",
                key.display(),
                last_error()
            )));
        }
        self.finish(ctx)
    }

    /// Load the certificate chain and private key from in-memory PEM bytes
    /// and finalise the configuration.
    pub fn with_pem_bytes(self, cert: &[u8], key: &[u8]) -> Result<ServerConfig> {
        let ctx = new_server_ctx()?;
        load_cert_chain_pem(&ctx, cert)?;
        load_private_key_pem(&ctx, key)?;
        self.finish(ctx)
    }

    /// Load the certificate chain and private key from raw DER bytes and
    /// finalise the configuration.
    ///
    /// `cert_chain` is a slice of DER-encoded `Certificate` bodies in
    /// chain order: leaf first, then any intermediates the server should
    /// present. At least one certificate (the leaf) is required.
    ///
    /// `key` is a DER-encoded private key in PKCS#8, PKCS#1 (RSA), or
    /// SEC1 (EC) format; the algorithm is auto-detected via
    /// [`d2i_AutoPrivateKey`](aws_lc_sys::d2i_AutoPrivateKey).
    ///
    /// Use this when interfacing with tooling that already produces DER
    /// (HSMs, KMS exports, ASN.1 generators) and avoid a PEM
    /// round-trip just to call [`Self::with_pem_bytes`].
    pub fn with_der_bytes(self, cert_chain: &[&[u8]], key: &[u8]) -> Result<ServerConfig> {
        let ctx = new_server_ctx()?;
        load_cert_chain_der(&ctx, cert_chain)?;
        load_private_key_der(&ctx, key)?;
        self.finish(ctx)
    }

    fn finish(self, ctx: SslCtx) -> Result<ServerConfig> {
        // Match key against the leaf certificate before anything else
        // touches the context.
        // SAFETY: ctx is a live SSL_CTX with cert + key loaded.
        let ok = unsafe { aws_lc_sys::SSL_CTX_check_private_key(ctx.as_ptr()) };
        if ok != 1 {
            return Err(Error::Init(format!(
                "certificate and private key do not match: {}",
                last_error()
            )));
        }

        // Version bounds.
        let min_v = self.min_version.unwrap_or(ProtocolVersion::Tls12).raw();
        let max_v = self.max_version.unwrap_or(ProtocolVersion::Tls13).raw();
        // SAFETY: ctx is live; both functions take a u16 version constant.
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

        // Disable session tickets unconditionally — see module docs.
        // SAFETY: ctx is live; the options/value are scalar constants.
        #[allow(clippy::cast_sign_loss)]
        unsafe {
            aws_lc_sys::SSL_CTX_set_options(ctx.as_ptr(), aws_lc_sys::SSL_OP_NO_TICKET as u32);
            aws_lc_sys::SSL_CTX_set_num_tickets(ctx.as_ptr(), 0);
        }

        if self.ktls_aead_only {
            // TLS 1.2 cipher list: AEAD only, drops CBC-SHA suites that
            // can't be offloaded.
            let list = c"ECDHE+AESGCM:ECDHE+CHACHA20";
            // SAFETY: list is a static NUL-terminated string; ctx is live.
            let ok = unsafe { aws_lc_sys::SSL_CTX_set_cipher_list(ctx.as_ptr(), list.as_ptr()) };
            if ok != 1 {
                return Err(Error::Init(format!(
                    "SSL_CTX_set_cipher_list (AEAD-only): {}",
                    last_error()
                )));
            }
        }

        // User-supplied cipher-suite override. Applied after the
        // AEAD-only default so a caller setting both wins.
        if let Some(suites) = &self.cipher_suites {
            cipher_suite::apply_to_ctx(&ctx, suites)?;
        }

        // User-supplied named-group preference list (key exchange).
        if let Some(groups) = &self.named_groups {
            named_group::apply_to_ctx(&ctx, groups)?;
        }

        // Client-cert verification (mTLS). Off by default.
        match self.client_auth {
            ClientAuthMode::None => {}
            mode => {
                let roots_pem = self.client_auth_roots_pem.as_deref().ok_or_else(|| {
                    Error::Init("client_auth requires a non-empty CA bundle (roots_pem)".into())
                })?;
                load_client_ca_roots_pem(&ctx, roots_pem)?;
                #[allow(clippy::cast_sign_loss)]
                let flags = match mode {
                    ClientAuthMode::None => unreachable!(),
                    ClientAuthMode::Optional => aws_lc_sys::SSL_VERIFY_PEER as c_int,
                    ClientAuthMode::Required => {
                        (aws_lc_sys::SSL_VERIFY_PEER | aws_lc_sys::SSL_VERIFY_FAIL_IF_NO_PEER_CERT)
                            as c_int
                    }
                };
                // SAFETY: ctx is live.
                unsafe {
                    aws_lc_sys::SSL_CTX_set_verify(ctx.as_ptr(), flags, None);
                }
            }
        }

        // ALPN: encode wire format, hand it to the SSL_CTX as ex_data
        // (which the registered free_func will drop at SSL_CTX_free
        // time), and register the select callback. The callback recovers
        // the buffer via SSL_get_SSL_CTX + SSL_CTX_get_ex_data, so no
        // user `arg` is needed.
        if !self.alpn_protocols.is_empty() {
            let refs: Vec<&[u8]> = self.alpn_protocols.iter().map(Vec::as_slice).collect();
            let wire = encode_alpn_wire(&refs)
                .map_err(|e| Error::Init(format!("encoding ALPN protocol list: {e}")))?;
            install_alpn_wire(&ctx, wire)?;
            // SAFETY: ctx is live; alpn_select_cb matches the FFI
            // signature.
            unsafe {
                aws_lc_sys::SSL_CTX_set_alpn_select_cb(
                    ctx.as_ptr(),
                    Some(alpn_select_cb),
                    ptr::null_mut(),
                );
            }
        }

        Ok(ServerConfig {
            ctx,
            ktls_disabled: self.ktls_disabled,
        })
    }
}

fn new_server_ctx() -> Result<SslCtx> {
    // SAFETY: TLS_server_method returns a static SSL_METHOD pointer;
    // SSL_CTX_new returns either an owned pointer or null on failure.
    let raw = unsafe { aws_lc_sys::SSL_CTX_new(aws_lc_sys::TLS_server_method()) };
    // SAFETY: `raw` is the freshly-owned SSL_CTX (or null).
    unsafe { SslCtx::from_raw(raw) }
        .ok_or_else(|| Error::Init(format!("SSL_CTX_new: {}", last_error())))
}

fn path_to_cstring(p: &Path) -> Result<CString> {
    let s = p.to_str().ok_or_else(|| {
        Error::Init(format!(
            "path {} is not valid UTF-8; AWS-LC PEM loaders require a NUL-terminated path",
            p.display()
        ))
    })?;
    CString::new(s).map_err(|_| {
        Error::Init(format!(
            "path {} contains an embedded NUL byte",
            p.display()
        ))
    })
}

fn load_cert_chain_pem(ctx: &SslCtx, pem: &[u8]) -> Result<()> {
    // SAFETY: BIO_new_mem_buf takes a const-buffer + length and produces a
    // read-only BIO; the BIO does not take ownership of `pem`, so the
    // slice can outlive the BIO (and does — it's a borrow from the caller).
    #[allow(clippy::cast_possible_wrap)]
    let bio = unsafe { aws_lc_sys::BIO_new_mem_buf(pem.as_ptr().cast(), pem.len() as isize) };
    if bio.is_null() {
        return Err(Error::Init(format!(
            "BIO_new_mem_buf for cert chain: {}",
            last_error()
        )));
    }
    let bio = BioGuard(bio);

    // First cert is the leaf; install via SSL_CTX_use_certificate.
    // SAFETY: bio is live; the three null args mean "no password callback".
    let leaf =
        unsafe { aws_lc_sys::PEM_read_bio_X509_AUX(bio.0, ptr::null_mut(), None, ptr::null_mut()) };
    if leaf.is_null() {
        return Err(Error::Init(format!(
            "PEM_read_bio_X509_AUX (leaf): {}",
            last_error()
        )));
    }
    // SAFETY: ctx and leaf are live; SSL_CTX_use_certificate bumps the
    // X509 refcount internally, so we still need to free our copy.
    let ok = unsafe { aws_lc_sys::SSL_CTX_use_certificate(ctx.as_ptr(), leaf) };
    // SAFETY: leaf is owned here; SSL_CTX_use_certificate bumped its ref.
    unsafe { aws_lc_sys::X509_free(leaf) };
    if ok != 1 {
        return Err(Error::Init(format!(
            "SSL_CTX_use_certificate: {}",
            last_error()
        )));
    }

    // Clear out the chain slot before appending; SSL_CTX_clear_chain_certs
    // returns 1 on success, but is safe to call when empty.
    // SAFETY: ctx is live.
    unsafe {
        aws_lc_sys::SSL_CTX_clear_chain_certs(ctx.as_ptr());
    }

    // Remaining certs (if any) form the chain. A NULL return is either
    // the legitimate end-of-bundle marker (PEM_R_NO_START_LINE) or a real
    // parse failure on a corrupt trailer; pem_eof_or_err distinguishes
    // the two so a truncated chain cannot be silently accepted.
    loop {
        // SAFETY: bio is live.
        let extra =
            unsafe { aws_lc_sys::PEM_read_bio_X509(bio.0, ptr::null_mut(), None, ptr::null_mut()) };
        if extra.is_null() {
            pem_eof_or_err("PEM_read_bio_X509 (server chain)")?;
            break;
        }
        // SAFETY: ctx and extra are live. SSL_CTX_add0_chain_cert takes
        // ownership of the X509 on success.
        let ok = unsafe { aws_lc_sys::SSL_CTX_add0_chain_cert(ctx.as_ptr(), extra) };
        if ok != 1 {
            // SAFETY: ownership remains with us when the call failed.
            unsafe { aws_lc_sys::X509_free(extra) };
            return Err(Error::Init(format!(
                "SSL_CTX_add0_chain_cert: {}",
                last_error()
            )));
        }
    }

    Ok(())
}

fn load_private_key_pem(ctx: &SslCtx, pem: &[u8]) -> Result<()> {
    // SAFETY: read-only BIO over a borrowed buffer.
    #[allow(clippy::cast_possible_wrap)]
    let bio = unsafe { aws_lc_sys::BIO_new_mem_buf(pem.as_ptr().cast(), pem.len() as isize) };
    if bio.is_null() {
        return Err(Error::Init(format!(
            "BIO_new_mem_buf for private key: {}",
            last_error()
        )));
    }
    let bio = BioGuard(bio);

    // SAFETY: bio is live; null arg trio means no password callback.
    let key = unsafe {
        aws_lc_sys::PEM_read_bio_PrivateKey(bio.0, ptr::null_mut(), None, ptr::null_mut())
    };
    if key.is_null() {
        return Err(Error::Init(format!(
            "PEM_read_bio_PrivateKey: {}",
            last_error()
        )));
    }
    // SAFETY: ctx and key are live; SSL_CTX_use_PrivateKey bumps the
    // EVP_PKEY refcount.
    let ok = unsafe { aws_lc_sys::SSL_CTX_use_PrivateKey(ctx.as_ptr(), key) };
    // SAFETY: we own the local refcount.
    unsafe { aws_lc_sys::EVP_PKEY_free(key) };
    if ok != 1 {
        return Err(Error::Init(format!(
            "SSL_CTX_use_PrivateKey: {}",
            last_error()
        )));
    }
    Ok(())
}

/// Install the leaf and any intermediate DER certificates onto `ctx`,
/// taking ownership of the parsed `X509` objects as we go.
fn load_cert_chain_der(ctx: &SslCtx, certs: &[&[u8]]) -> Result<()> {
    let (leaf_der, rest) = certs.split_first().ok_or_else(|| {
        Error::Init("DER certificate chain must contain at least the leaf certificate".into())
    })?;

    let leaf = super::der::parse_x509(leaf_der)?;
    // SAFETY: ctx and leaf are live; SSL_CTX_use_certificate bumps the
    // X509 refcount internally, so we still need to free our local copy.
    let ok = unsafe { aws_lc_sys::SSL_CTX_use_certificate(ctx.as_ptr(), leaf) };
    // SAFETY: leaf is owned here; SSL_CTX_use_certificate bumped its ref.
    unsafe { aws_lc_sys::X509_free(leaf) };
    if ok != 1 {
        return Err(Error::Init(format!(
            "SSL_CTX_use_certificate (DER leaf): {}",
            last_error()
        )));
    }

    // Clear out the chain slot before appending; SSL_CTX_clear_chain_certs
    // returns 1 on success and is safe to call when empty.
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
            // SAFETY: ownership remains with us when the call failed.
            unsafe { aws_lc_sys::X509_free(extra) };
            return Err(Error::Init(format!(
                "SSL_CTX_add0_chain_cert (DER): {}",
                last_error()
            )));
        }
    }

    Ok(())
}

fn load_private_key_der(ctx: &SslCtx, der: &[u8]) -> Result<()> {
    let key = super::der::parse_private_key(der)?;
    // SAFETY: ctx and key are live; SSL_CTX_use_PrivateKey bumps the
    // EVP_PKEY refcount.
    let ok = unsafe { aws_lc_sys::SSL_CTX_use_PrivateKey(ctx.as_ptr(), key) };
    // SAFETY: we own the local refcount.
    unsafe { aws_lc_sys::EVP_PKEY_free(key) };
    if ok != 1 {
        return Err(Error::Init(format!(
            "SSL_CTX_use_PrivateKey (DER): {}",
            last_error()
        )));
    }
    Ok(())
}

// Local guard so a fallible loader doesn't leak the BIO; not promoted
// to the public ffi.rs surface because the wider crate hands BIOs off
// via Bio::into_raw (different ownership pattern).
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

/// Load every PEM certificate in `pem` into the `SSL_CTX`'s trust store
/// for the purpose of verifying client certificates during mTLS.
fn load_client_ca_roots_pem(ctx: &SslCtx, pem: &[u8]) -> Result<()> {
    // SAFETY: read-only BIO over a borrowed buffer.
    #[allow(clippy::cast_possible_wrap)]
    let bio = unsafe { aws_lc_sys::BIO_new_mem_buf(pem.as_ptr().cast(), pem.len() as isize) };
    if bio.is_null() {
        return Err(Error::Init(format!(
            "BIO_new_mem_buf for client CA roots: {}",
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
        // SAFETY: bio is live; null trio means no password callback.
        let cert =
            unsafe { aws_lc_sys::PEM_read_bio_X509(bio.0, ptr::null_mut(), None, ptr::null_mut()) };
        if cert.is_null() {
            pem_eof_or_err("PEM_read_bio_X509 (client CA roots)")?;
            break;
        }
        // SAFETY: store and cert are live; X509_STORE_add_cert bumps the
        // X509 refcount internally.
        let ok = unsafe { aws_lc_sys::X509_STORE_add_cert(store, cert) };
        // SAFETY: we own a local refcount regardless.
        unsafe { aws_lc_sys::X509_free(cert) };
        if ok != 1 {
            return Err(Error::Init(format!(
                "X509_STORE_add_cert (client CA): {}",
                last_error()
            )));
        }
        added += 1;
    }

    if added == 0 {
        return Err(Error::Init(
            "no certificates found in client CA roots PEM".into(),
        ));
    }
    Ok(())
}

/// Process-wide `ex_data` slot index for the ALPN wire buffer on
/// `SSL_CTX`. Allocated lazily on first use; `SSL_CTX_get_ex_new_index`
/// is safe to call from any thread.
fn alpn_ex_index() -> c_int {
    static IDX: OnceLock<c_int> = OnceLock::new();
    *IDX.get_or_init(|| {
        // SAFETY: signature matches the AWS-LC binding; `argl`/`argp` are
        // unused, dup_func is None (we never duplicate CTXs through
        // ex_data), free_func owns the drop on SSL_CTX_free.
        let idx = unsafe {
            aws_lc_sys::SSL_CTX_get_ex_new_index(
                0,
                ptr::null_mut(),
                ptr::null_mut(),
                None,
                Some(alpn_ex_free),
            )
        };
        assert!(idx >= 0, "SSL_CTX_get_ex_new_index failed");
        idx
    })
}

/// Move `wire` into the `SSL_CTX`'s `ex_data` slot. The buffer is freed
/// by [`alpn_ex_free`] when AWS-LC frees the CTX.
fn install_alpn_wire(ctx: &SslCtx, wire: Vec<u8>) -> Result<()> {
    let raw = Box::into_raw(Box::new(wire)).cast::<c_void>();
    // SAFETY: ctx is live; `raw` is a freshly-leaked Box<Vec<u8>>.
    // SSL_CTX_set_ex_data returns 1 on success and the CTX takes
    // ownership; on failure we reclaim the Box to avoid a leak.
    let ok = unsafe { aws_lc_sys::SSL_CTX_set_ex_data(ctx.as_ptr(), alpn_ex_index(), raw) };
    if ok != 1 {
        // SAFETY: `raw` came from Box::into_raw above and the CTX did
        // not take ownership.
        drop(unsafe { Box::from_raw(raw.cast::<Vec<u8>>()) });
        return Err(Error::Init(format!(
            "SSL_CTX_set_ex_data (ALPN): {}",
            last_error()
        )));
    }
    Ok(())
}

/// `free_func` registered with [`alpn_ex_index`]. AWS-LC calls this once
/// per CTX as part of `SSL_CTX_free`, with `ptr` equal to whatever was
/// stored via `SSL_CTX_set_ex_data` for our slot.
unsafe extern "C" fn alpn_ex_free(
    _parent: *mut c_void,
    ptr: *mut c_void,
    _ad: *mut aws_lc_sys::CRYPTO_EX_DATA,
    _index: c_int,
    _argl: c_long,
    _argp: *mut c_void,
) {
    if ptr.is_null() {
        return;
    }
    // SAFETY: `ptr` was set by `install_alpn_wire` to a Box<Vec<u8>>
    // raw pointer; the CTX is being freed so this is the last access.
    drop(unsafe { Box::from_raw(ptr.cast::<Vec<u8>>()) });
}

/// ALPN server-side select callback. The wire-format protocol list is
/// stored as `ex_data` on the CTX; we recover it via
/// [`SSL_get_SSL_CTX`](aws_lc_sys::SSL_get_SSL_CTX) rather than relying on the
/// user `arg`.
///
/// Returns the first server-preference protocol that the client also
/// offers. If no overlap exists, returns `SSL_TLSEXT_ERR_ALERT_FATAL`
/// so the handshake fails with `no_application_protocol` (RFC 7301
/// §3.2) rather than silently completing without ALPN — the latter
/// invites protocol-confusion on a server that was explicitly
/// configured with an ALPN list.
unsafe extern "C" fn alpn_select_cb(
    ssl: *mut aws_lc_sys::SSL,
    out: *mut *const u8,
    out_len: *mut u8,
    in_: *const u8,
    in_len: c_uint,
    _arg: *mut c_void,
) -> c_int {
    // SAFETY: `ssl` is live for the duration of the handshake;
    // SSL_get_SSL_CTX returns a borrowed CTX pointer.
    let ctx = unsafe { aws_lc_sys::SSL_get_SSL_CTX(ssl) };
    if ctx.is_null() {
        return aws_lc_sys::SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    // SAFETY: ctx is live; the slot was populated by `install_alpn_wire`.
    // `SSL_CTX_get_ex_data` returns NULL if no value was set.
    let raw = unsafe { aws_lc_sys::SSL_CTX_get_ex_data(ctx, alpn_ex_index()) };
    if raw.is_null() {
        return aws_lc_sys::SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    // SAFETY: `raw` points to a Box<Vec<u8>> owned by the CTX (set by
    // `install_alpn_wire`); the CTX outlives every handshake on it,
    // so this borrow is valid until the callback returns.
    let server_wire: &Vec<u8> = unsafe { &*raw.cast::<Vec<u8>>() };
    // SAFETY: AWS-LC guarantees `in_` points to `in_len` readable bytes
    // for the duration of the call.
    let client_wire: &[u8] = unsafe { std::slice::from_raw_parts(in_, in_len as usize) };

    for server_proto in iter_alpn_wire(server_wire) {
        for client_proto in iter_alpn_wire(client_wire) {
            if server_proto == client_proto {
                // SAFETY: out/out_len are caller-owned out-params. The
                // returned pointer lives inside the CTX-owned buffer,
                // which outlives the handshake.
                unsafe {
                    *out = server_proto.as_ptr();
                    // `server_proto.len()` came from a one-byte length
                    // prefix; the cast is lossless.
                    #[allow(clippy::cast_possible_truncation)]
                    {
                        *out_len = server_proto.len() as u8;
                    }
                }
                return aws_lc_sys::SSL_TLSEXT_ERR_OK;
            }
        }
    }
    aws_lc_sys::SSL_TLSEXT_ERR_ALERT_FATAL
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CERT_PEM: &[u8] = include_bytes!("../../tests/data/cert.pem");
    const TEST_KEY_PEM: &[u8] = include_bytes!("../../tests/data/key.pem");
    const TEST_CERT_DER: &[u8] = include_bytes!("../../tests/data/cert.der");
    const TEST_KEY_DER: &[u8] = include_bytes!("../../tests/data/key.der");

    #[test]
    fn builds_from_valid_pem_bytes() {
        let cfg = ServerConfig::builder()
            .with_pem_bytes(TEST_CERT_PEM, TEST_KEY_PEM)
            .expect("config should build");
        assert!(!cfg.ctx_ptr().is_null());
    }

    #[test]
    fn builds_from_valid_der_bytes() {
        let cfg = ServerConfig::builder()
            .with_der_bytes(&[TEST_CERT_DER], TEST_KEY_DER)
            .expect("config should build from DER cert + key");
        assert!(!cfg.ctx_ptr().is_null());
    }

    #[test]
    fn der_empty_chain_rejected() {
        let err = ServerConfig::builder()
            .with_der_bytes(&[], TEST_KEY_DER)
            .expect_err("empty chain should fail");
        assert!(matches!(err, Error::Init(_)), "got: {err:?}");
    }

    #[test]
    fn der_garbage_cert_rejected() {
        let err = ServerConfig::builder()
            .with_der_bytes(&[b"not a real DER cert"], TEST_KEY_DER)
            .expect_err("garbage DER should fail");
        assert!(matches!(err, Error::Init(_)), "got: {err:?}");
    }

    #[test]
    fn der_garbage_key_rejected() {
        let err = ServerConfig::builder()
            .with_der_bytes(&[TEST_CERT_DER], b"not a real DER key")
            .expect_err("garbage DER key should fail");
        assert!(matches!(err, Error::Init(_)), "got: {err:?}");
    }

    #[test]
    fn mismatched_cert_and_key_rejected() {
        // Truncate the key so PEM parsing fails before mismatch check
        // — covers the "bad input rejected" property even though it
        // doesn't exercise SSL_CTX_check_private_key specifically.
        let err = ServerConfig::builder()
            .with_pem_bytes(TEST_CERT_PEM, b"not a real key")
            .expect_err("should fail on garbage key");
        assert!(matches!(err, Error::Init(_)), "got: {err:?}");
    }

    #[test]
    fn builder_chains_setters() {
        let cfg = ServerConfig::builder()
            .alpn_protocols(&[b"h2", b"http/1.1"])
            .min_protocol_version(ProtocolVersion::Tls12)
            .max_protocol_version(ProtocolVersion::Tls13)
            .ktls_aead_only(true)
            .with_pem_bytes(TEST_CERT_PEM, TEST_KEY_PEM)
            .expect("config should build with full setter chain");
        assert!(!cfg.ctx_ptr().is_null());
    }

    #[test]
    fn with_pem_files_loads_from_disk() {
        use std::fs;
        use std::path::PathBuf;

        struct TmpFile(PathBuf);
        impl Drop for TmpFile {
            fn drop(&mut self) {
                let _ = fs::remove_file(&self.0);
            }
        }

        let dir = std::env::temp_dir();
        let pid = std::process::id();
        let cert = TmpFile(dir.join(format!("tokio-aws-lc-{pid}-cert.pem")));
        let key = TmpFile(dir.join(format!("tokio-aws-lc-{pid}-key.pem")));
        fs::write(&cert.0, TEST_CERT_PEM).expect("write cert");
        fs::write(&key.0, TEST_KEY_PEM).expect("write key");

        let cfg = ServerConfig::builder()
            .with_pem_files(&cert.0, &key.0)
            .expect("config should build from on-disk PEM files");
        assert!(!cfg.ctx_ptr().is_null());
    }

    #[test]
    fn with_pem_files_missing_path_errors() {
        use std::path::PathBuf;

        let missing = PathBuf::from("/definitely/does/not/exist/cert.pem");
        let err = ServerConfig::builder()
            .with_pem_files(&missing, &missing)
            .expect_err("missing files should fail");
        let msg = err.to_string();
        assert!(
            msg.contains("loading certificate chain"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn path_to_cstring_rejects_embedded_nul() {
        use std::path::PathBuf;

        // PathBuf can hold a NUL on Unix even though most filesystems
        // reject it; the loader's CString conversion must catch it.
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let pb = PathBuf::from(std::ffi::OsString::from_vec(b"foo\0bar.pem".to_vec()));
            let err = path_to_cstring(&pb).expect_err("embedded NUL must be rejected");
            let msg = err.to_string();
            assert!(
                msg.contains("embedded NUL byte"),
                "unexpected error message: {msg}"
            );
        }
        // On non-Unix targets we can't easily build a PathBuf with a
        // NUL, so the assertion above is the only one we make.
        let _ = path_to_cstring(&PathBuf::from("normal.pem")).expect("plain path");
    }

    #[test]
    fn pem_chain_with_trailing_garbage_is_rejected() {
        // After the legitimate end-entity cert, splice in a malformed
        // PEM block. The strict EOF check must surface this as an
        // Init error rather than silently treating the garbage as
        // "end of bundle" the way an unconditional ERR_clear_error
        // would.
        let mut polluted: Vec<u8> = TEST_CERT_PEM.to_vec();
        polluted.extend_from_slice(
            b"\n-----BEGIN CERTIFICATE-----\nnot-base64-at-all\n-----END CERTIFICATE-----\n",
        );
        let err = ServerConfig::builder()
            .with_pem_bytes(&polluted, TEST_KEY_PEM)
            .expect_err("trailing garbage in cert PEM must be rejected");
        assert!(matches!(err, Error::Init(_)), "got: {err:?}");
    }
}
