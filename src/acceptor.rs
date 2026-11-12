//! Server-side handshake entry point.

use std::ffi::CStr;
use std::fmt;
use std::os::fd::AsRawFd as _;
use std::os::raw::{c_int, c_long, c_void};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::sync::{Arc, OnceLock};

use crate::error::{last_error, Error, Result};
use crate::ffi::{Ssl, SslCtx};
use crate::stream::{attach_socket_bio, drive_handshake, TlsStream};
use crate::ServerConfig;

/// Acceptor that hands out [`TlsStream`]s on top of inbound TCP connections.
///
/// Cheap to clone (wraps an `Arc`); one acceptor can be shared across
/// many tasks.
#[derive(Clone, Debug)]
pub struct TlsAcceptor {
    cfg: AcceptorConfig,
}

#[derive(Clone, Debug)]
enum AcceptorConfig {
    Fixed(Arc<ServerConfig>),
    Resolving(Arc<Resolver>),
}

type Resolve = dyn Fn(Option<&str>) -> Option<Arc<ServerConfig>> + Send + Sync;

struct Resolver {
    ctx: SslCtx,
    resolve: Box<Resolve>,
}

impl fmt::Debug for Resolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Resolver").finish_non_exhaustive()
    }
}

// SAFETY: ctx is immutable after construction; resolve is Send + Sync.
unsafe impl Sync for Resolver {}

struct SniState {
    resolver: Arc<Resolver>,
    selected: Option<Arc<ServerConfig>>,
    error: Option<String>,
}

impl TlsAcceptor {
    /// Build an acceptor from a finished [`ServerConfig`]. Accepts
    /// either an `Arc<ServerConfig>` (cheap clone of an existing
    /// `Arc`) or an owned `ServerConfig` (auto-wrapped in a fresh
    /// `Arc`).
    pub fn new(cfg: impl Into<Arc<ServerConfig>>) -> Self {
        Self {
            cfg: AcceptorConfig::Fixed(cfg.into()),
        }
    }

    /// Select a complete server configuration from the client's SNI before
    /// negotiating TLS or requesting a client certificate.
    ///
    /// The resolver receives an ASCII-lowercased hostname, or `None` when
    /// SNI is absent (including connections made to IP literals). Returning
    /// `None` rejects the handshake; return a default configuration explicitly
    /// to allow fallback. No wildcard matching or IDNA conversion is performed.
    /// Non-ASCII names are rejected.
    ///
    /// The resolver runs synchronously during the handshake and must not block.
    /// It may run concurrently for different connections. A resolver panic
    /// rejects the handshake instead of unwinding through AWS-LC, unless the
    /// application is compiled with `panic = "abort"`.
    pub fn with_sni_resolver<F>(resolve: F) -> Result<Self>
    where
        F: Fn(Option<&str>) -> Option<Arc<ServerConfig>> + Send + Sync + 'static,
    {
        let ctx =
            unsafe { SslCtx::from_raw(aws_lc_sys::SSL_CTX_new(aws_lc_sys::TLS_server_method())) }
                .ok_or_else(|| Error::Init(format!("SSL_CTX_new (SNI): {}", last_error())))?;
        sni_ex_index()?;
        unsafe {
            aws_lc_sys::SSL_CTX_set_select_certificate_cb(ctx.as_ptr(), Some(select_certificate));
            aws_lc_sys::SSL_CTX_set_options(
                ctx.as_ptr(),
                u32::try_from(aws_lc_sys::SSL_OP_NO_TICKET).expect("option fits in u32"),
            );
            aws_lc_sys::SSL_CTX_set_num_tickets(ctx.as_ptr(), 0);
            aws_lc_sys::SSL_CTX_set_session_cache_mode(
                ctx.as_ptr(),
                aws_lc_sys::SSL_SESS_CACHE_OFF,
            );
        }
        Ok(Self {
            cfg: AcceptorConfig::Resolving(Arc::new(Resolver {
                ctx,
                resolve: Box::new(resolve),
            })),
        })
    }

    /// Drive the TLS handshake to completion against an already-accepted
    /// TCP connection. Resolves to a [`TlsStream`] on success.
    pub async fn accept(&self, tcp: tokio::net::TcpStream) -> Result<TlsStream> {
        let ctx = match &self.cfg {
            AcceptorConfig::Fixed(cfg) => cfg.ctx_ptr(),
            AcceptorConfig::Resolving(resolver) => resolver.ctx.as_ptr(),
        };
        let mut ssl = new_ssl(ctx)?;
        if let AcceptorConfig::Resolving(resolver) = &self.cfg {
            let index = sni_ex_index()?;
            let state = Box::new(SniState {
                resolver: Arc::clone(resolver),
                selected: None,
                error: None,
            });
            let raw = Box::into_raw(state);
            if unsafe { aws_lc_sys::SSL_set_ex_data(ssl.as_ptr(), index, raw.cast()) } != 1 {
                drop(unsafe { Box::from_raw(raw) });
                return Err(Error::Init(format!(
                    "SSL_set_ex_data (SNI): {}",
                    last_error()
                )));
            }
        }
        // SAFETY: ssl is fresh; `tcp` owns the non-blocking socket fd
        // for the rest of this function and the resulting TlsStream.
        unsafe {
            attach_socket_bio(&mut ssl, tcp.as_raw_fd())?;
            aws_lc_sys::SSL_set_accept_state(ssl.as_ptr());
        }
        // SAFETY: ssl is wired to tcp's fd and set to accept state.
        if let Err(error) = unsafe { drive_handshake(&mut ssl, &tcp).await } {
            if let Some(detail) = sni_state(&ssl).and_then(|state| state.error.as_ref()) {
                return Err(Error::Handshake(detail.clone()));
            }
            return Err(error);
        }
        let ktls_disabled = match &self.cfg {
            AcceptorConfig::Fixed(cfg) => cfg.ktls_disabled,
            AcceptorConfig::Resolving(_) => {
                sni_state(&ssl)
                    .and_then(|state| state.selected.as_ref())
                    .ok_or_else(|| {
                        Error::Handshake("SNI resolver did not select a configuration".into())
                    })?
                    .ktls_disabled
            }
        };
        let mut stream = TlsStream::from_parts(ssl, tcp, ktls_disabled);
        stream.try_auto_install_ktls()?;
        Ok(stream)
    }
}

fn new_ssl(ctx: *mut aws_lc_sys::SSL_CTX) -> Result<Ssl> {
    // SAFETY: ctx is a live SSL_CTX borrowed from this acceptor; SSL_new
    // returns either an owned SSL or null on alloc failure.
    let raw = unsafe { aws_lc_sys::SSL_new(ctx) };
    // SAFETY: `raw` is the freshly-owned SSL (or null).
    unsafe { Ssl::from_raw(raw) }.ok_or_else(|| Error::Init(format!("SSL_new: {}", last_error())))
}

fn sni_ex_index() -> Result<c_int> {
    static INDEX: OnceLock<c_int> = OnceLock::new();
    let index = *INDEX.get_or_init(|| unsafe {
        aws_lc_sys::SSL_get_ex_new_index(
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            None,
            Some(sni_state_free),
        )
    });
    if index < 0 {
        return Err(Error::Init("SSL_get_ex_new_index (SNI) failed".into()));
    }
    Ok(index)
}

fn sni_state(ssl: &Ssl) -> Option<&SniState> {
    let index = sni_ex_index().ok()?;
    unsafe {
        aws_lc_sys::SSL_get_ex_data(ssl.as_ptr(), index)
            .cast::<SniState>()
            .as_ref()
    }
}

fn drop_panic_payload(payload: Box<dyn std::any::Any + Send>) {
    if let Err(nested) = catch_unwind(AssertUnwindSafe(|| drop(payload))) {
        std::mem::forget(nested);
    }
}

unsafe extern "C" fn sni_state_free(
    _parent: *mut c_void,
    raw: *mut c_void,
    _data: *mut aws_lc_sys::CRYPTO_EX_DATA,
    _index: c_int,
    _argl: c_long,
    _argp: *mut c_void,
) {
    if !raw.is_null() {
        if let Err(payload) = catch_unwind(AssertUnwindSafe(|| {
            drop(unsafe { Box::from_raw(raw.cast::<SniState>()) });
        })) {
            drop_panic_payload(payload);
        }
    }
}

unsafe extern "C" fn select_certificate(
    hello: *const aws_lc_sys::SSL_CLIENT_HELLO,
) -> aws_lc_sys::ssl_select_cert_result_t {
    let ssl = unsafe { (*hello).ssl };
    let Ok(index) = sni_ex_index() else {
        return aws_lc_sys::ssl_select_cert_result_t_ssl_select_cert_error;
    };
    let raw = unsafe { aws_lc_sys::SSL_get_ex_data(ssl, index).cast::<SniState>() };
    let Some(state) = (unsafe { raw.as_mut() }) else {
        return aws_lc_sys::ssl_select_cert_result_t_ssl_select_cert_error;
    };
    let result = catch_unwind(AssertUnwindSafe(|| -> Result<()> {
        if state.selected.is_some() {
            return Ok(());
        }
        let name = unsafe {
            aws_lc_sys::SSL_get_servername(ssl, aws_lc_sys::TLSEXT_NAMETYPE_host_name as c_int)
        };
        let name = if name.is_null() {
            None
        } else {
            let name = unsafe { CStr::from_ptr(name) }.to_bytes();
            if !name.is_ascii() {
                return Err(Error::Handshake("non-ASCII SNI hostname".into()));
            }
            Some(String::from_utf8_lossy(name).to_ascii_lowercase())
        };
        let cfg = (state.resolver.resolve)(name.as_deref())
            .ok_or_else(|| Error::Handshake("SNI resolver rejected the connection".into()))?;
        unsafe { cfg.apply_to_ssl(ssl)? };
        state.selected = Some(cfg);
        Ok(())
    }));
    match result {
        Ok(Ok(())) => aws_lc_sys::ssl_select_cert_result_t_ssl_select_cert_success,
        Ok(Err(error)) => {
            state.error = Some(error.to_string());
            aws_lc_sys::ssl_select_cert_result_t_ssl_select_cert_error
        }
        Err(payload) => {
            drop_panic_payload(payload);
            state.error = Some("SNI resolver panicked".into());
            aws_lc_sys::ssl_select_cert_result_t_ssl_select_cert_error
        }
    }
}
