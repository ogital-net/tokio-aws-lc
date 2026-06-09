//! Client-side handshake entry point.

use std::ffi::CString;
use std::net::IpAddr;
use std::os::fd::AsRawFd as _;
use std::sync::Arc;

use crate::error::{last_error, Error, Result};
use crate::ffi::Ssl;
use crate::stream::{attach_socket_bio, drive_handshake, TlsStream};
use crate::ClientConfig;

/// Connector that drives outbound TLS handshakes on top of an
/// already-connected TCP stream.
///
/// Cheap to clone (it's just an `Arc`); one connector can fan out across
/// many tasks.
#[derive(Clone, Debug)]
pub struct TlsConnector {
    cfg: Arc<ClientConfig>,
}

impl TlsConnector {
    /// Build a connector from a finished [`ClientConfig`]. Accepts
    /// either an `Arc<ClientConfig>` (cheap clone of an existing
    /// `Arc`) or an owned `ClientConfig` (auto-wrapped in a fresh
    /// `Arc`).
    pub fn new(cfg: impl Into<Arc<ClientConfig>>) -> Self {
        Self { cfg: cfg.into() }
    }

    /// Drive the TLS handshake to completion against an already-connected
    /// TCP stream.
    ///
    /// `server_name` is the peer identity to authenticate. It may be:
    ///
    /// - a DNS name (e.g. `"example.com"`) — sent as the SNI extension
    ///   and matched against the certificate's DNS SANs / CN; or
    /// - an IP-address literal (e.g. `"10.0.0.5"` or `"2001:db8::1"`)
    ///   — *not* sent as SNI (RFC 6066 §3 forbids IPs in SNI) and
    ///   matched against the certificate's iPAddress SANs.
    ///
    /// Both checks happen inside libssl as part of the handshake; a
    /// mismatch fails the handshake with a verification error. Disabling
    /// verification on the underlying [`ClientConfig`] disables this
    /// check too.
    ///
    /// # Errors
    ///
    /// - `Error::Init` if `server_name` is empty, contains a NUL byte,
    ///   or libssl rejects it.
    /// - `Error::Handshake` on any TLS handshake failure.
    pub async fn connect(
        &self,
        server_name: &str,
        tcp: tokio::net::TcpStream,
    ) -> Result<TlsStream> {
        if server_name.is_empty() {
            return Err(Error::Init("server_name must not be empty".into()));
        }
        let mut ssl = new_ssl(&self.cfg)?;

        let name_c = CString::new(server_name)
            .map_err(|_| Error::Init("server_name contains an embedded NUL byte".into()))?;

        // RFC 6066 §3: the SNI extension carries DNS names only, never
        // IP literals. Route IP-literal peers through the iPAddress SAN
        // path; everything else gets SNI + DNS-SAN/CN matching.
        match server_name.parse::<IpAddr>() {
            Ok(_) => {
                // SAFETY: ssl is fresh; SSL_get0_param returns a
                // borrowed X509_VERIFY_PARAM owned by the SSL handle.
                // X509_VERIFY_PARAM_set1_ip_asc accepts the same
                // textual forms as `IpAddr::FromStr` (dotted-quad and
                // RFC 5952 IPv6); returns 1 on success.
                let param = unsafe { aws_lc_sys::SSL_get0_param(ssl.as_ptr()) };
                if param.is_null() {
                    return Err(Error::Init(
                        "SSL_get0_param returned null for fresh SSL".into(),
                    ));
                }
                let ok =
                    unsafe { aws_lc_sys::X509_VERIFY_PARAM_set1_ip_asc(param, name_c.as_ptr()) };
                if ok != 1 {
                    return Err(Error::Init(format!(
                        "X509_VERIFY_PARAM_set1_ip_asc({server_name}): {}",
                        last_error()
                    )));
                }
            }
            Err(_) => {
                // SAFETY: ssl is fresh; the CString lives for the call.
                // Both setters either succeed or queue an error.
                unsafe {
                    if aws_lc_sys::SSL_set_tlsext_host_name(ssl.as_ptr(), name_c.as_ptr()) != 1 {
                        return Err(Error::Init(format!(
                            "SSL_set_tlsext_host_name({server_name}): {}",
                            last_error()
                        )));
                    }
                    if aws_lc_sys::SSL_set1_host(ssl.as_ptr(), name_c.as_ptr()) != 1 {
                        return Err(Error::Init(format!(
                            "SSL_set1_host({server_name}): {}",
                            last_error()
                        )));
                    }
                }
            }
        }

        // SAFETY: ssl is fresh; `tcp` owns the non-blocking socket fd
        // for the rest of this function and the resulting TlsStream.
        unsafe {
            attach_socket_bio(&mut ssl, tcp.as_raw_fd())?;
            aws_lc_sys::SSL_set_connect_state(ssl.as_ptr());
        }
        // SAFETY: ssl is wired to tcp's fd and set to connect state.
        unsafe {
            drive_handshake(&mut ssl, &tcp).await?;
        }
        let mut stream = TlsStream::from_parts(ssl, tcp, self.cfg.ktls_disabled);
        stream.try_auto_install_ktls()?;
        Ok(stream)
    }
}

fn new_ssl(cfg: &ClientConfig) -> Result<Ssl> {
    // SAFETY: cfg.ctx_ptr() is a live SSL_CTX owned by `cfg`; SSL_new
    // returns either an owned SSL or null on alloc failure.
    let raw = unsafe { aws_lc_sys::SSL_new(cfg.ctx_ptr()) };
    // SAFETY: `raw` is the freshly-owned SSL (or null).
    unsafe { Ssl::from_raw(raw) }.ok_or_else(|| Error::Init(format!("SSL_new: {}", last_error())))
}
