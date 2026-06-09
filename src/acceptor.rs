//! Server-side handshake entry point.

use std::os::fd::AsRawFd as _;
use std::sync::Arc;

use crate::error::{last_error, Error, Result};
use crate::ffi::Ssl;
use crate::stream::{attach_socket_bio, drive_handshake, TlsStream};
use crate::ServerConfig;

/// Acceptor that hands out [`TlsStream`]s on top of inbound TCP connections.
///
/// Cheap to clone (it's just an `Arc`); one acceptor can be shared across
/// many tasks.
#[derive(Clone, Debug)]
pub struct TlsAcceptor {
    cfg: Arc<ServerConfig>,
}

impl TlsAcceptor {
    /// Build an acceptor from a finished [`ServerConfig`]. Accepts
    /// either an `Arc<ServerConfig>` (cheap clone of an existing
    /// `Arc`) or an owned `ServerConfig` (auto-wrapped in a fresh
    /// `Arc`).
    pub fn new(cfg: impl Into<Arc<ServerConfig>>) -> Self {
        Self { cfg: cfg.into() }
    }

    /// Drive the TLS handshake to completion against an already-accepted
    /// TCP connection. Resolves to a [`TlsStream`] on success.
    pub async fn accept(&self, tcp: tokio::net::TcpStream) -> Result<TlsStream> {
        let mut ssl = new_ssl(&self.cfg)?;
        // SAFETY: ssl is fresh; `tcp` owns the non-blocking socket fd
        // for the rest of this function and the resulting TlsStream.
        unsafe {
            attach_socket_bio(&mut ssl, tcp.as_raw_fd())?;
            aws_lc_sys::SSL_set_accept_state(ssl.as_ptr());
        }
        // SAFETY: ssl is wired to tcp's fd and set to accept state.
        unsafe {
            drive_handshake(&mut ssl, &tcp).await?;
        }
        let mut stream = TlsStream::from_parts(ssl, tcp, self.cfg.ktls_disabled);
        stream.try_auto_install_ktls()?;
        Ok(stream)
    }
}

fn new_ssl(cfg: &ServerConfig) -> Result<Ssl> {
    // SAFETY: cfg.ctx_ptr() is a live SSL_CTX owned by `cfg`; SSL_new
    // returns either an owned SSL or null on alloc failure.
    let raw = unsafe { aws_lc_sys::SSL_new(cfg.ctx_ptr()) };
    // SAFETY: `raw` is the freshly-owned SSL (or null).
    unsafe { Ssl::from_raw(raw) }.ok_or_else(|| Error::Init(format!("SSL_new: {}", last_error())))
}
