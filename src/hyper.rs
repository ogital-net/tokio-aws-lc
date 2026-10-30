//! `hyper` 1.x integration. Enable `hyper-server` or `hyper-client`
//! individually, or `hyper` for both adapters.
//!
//! Two pieces, both deliberately thin:
//!
//! * `HyperAcceptor` (`hyper-server`) wraps a [`crate::TlsAcceptor`] and produces a
//!   [`hyper_util::rt::TokioIo<TlsStream>`] ready to feed into
//!   `hyper_util::server::conn::auto::Builder::serve_connection`.
//!   Mirrors the shape of the `hyper-rustls/examples/server.rs`
//!   `TlsAcceptor`.
//! * `HttpsConnector` (`hyper-client`) is a `tower_service::Service<Uri>` that
//!   layers our [`crate::TlsConnector`] on top of `hyper_util`'s
//!   `HttpConnector` for the TCP step, returning
//!   `TokioIo<TlsStream>` on success. Slots into
//!   `hyper_util::client::legacy::Client::builder(...).build(https)`
//!   the same way `hyper-rustls`'s `HttpsConnector` does.
//!
//! Swap the `use` line and the connector constructor to move from
//! `hyper-rustls` / `hyper-tls`. No type-level compatibility exists;
//! concrete types differ.
//!
//! ALPN policy: a fresh `HttpsConnector` keeps the wrapped
//! [`crate::TlsConnector`]'s [`crate::ClientConfig`] ALPN as is. Configure
//! `["h2", "http/1.1"]` on the config builder for HTTP/2.

#[cfg(feature = "hyper-client")]
use std::future::Future;
#[cfg(feature = "hyper-client")]
use std::io;
#[cfg(feature = "hyper-client")]
use std::pin::Pin;
#[cfg(feature = "hyper-client")]
use std::task::{Context, Poll};

#[cfg(feature = "hyper-client")]
use http::Uri;
#[cfg(feature = "hyper-client")]
use hyper_util::client::legacy::connect::{Connected, Connection, HttpConnector};
use hyper_util::rt::TokioIo;
#[cfg(feature = "hyper-server")]
use tokio::net::TcpStream;
#[cfg(feature = "hyper-client")]
use tower_service::Service;

#[cfg(feature = "hyper-server")]
use crate::TlsAcceptor;
#[cfg(feature = "hyper-client")]
use crate::TlsConnector;
use crate::TlsStream;

/// Server-side acceptor adapter.
///
/// Cheap to clone; it holds the `Arc`-backed [`TlsAcceptor`] inside.
#[derive(Clone, Debug)]
#[cfg(feature = "hyper-server")]
pub struct HyperAcceptor {
    inner: TlsAcceptor,
}

#[cfg(feature = "hyper-server")]
impl HyperAcceptor {
    #[must_use]
    pub fn new(acceptor: TlsAcceptor) -> Self {
        Self { inner: acceptor }
    }

    /// Drive the TLS handshake on `tcp` and return a stream wrapped in
    /// [`TokioIo`], ready for `hyper`'s connection builder.
    pub async fn accept(&self, tcp: TcpStream) -> crate::error::Result<TokioIo<TlsStream>> {
        let stream = self.inner.accept(tcp).await?;
        Ok(TokioIo::new(stream))
    }

    /// Borrow the wrapped [`TlsAcceptor`].
    #[must_use]
    pub fn inner(&self) -> &TlsAcceptor {
        &self.inner
    }
}

#[cfg(feature = "hyper-server")]
impl From<TlsAcceptor> for HyperAcceptor {
    fn from(acceptor: TlsAcceptor) -> Self {
        Self::new(acceptor)
    }
}

/// Client-side HTTPS connector for use with
/// `hyper_util::client::legacy::Client::builder`.
///
/// Layers [`TlsConnector`] over an `HttpConnector` (or a clone you
/// supply) for the TCP step. The connector only handles `https://`
/// URIs; plain `http://` is rejected with an [`io::Error`].
#[derive(Clone, Debug)]
#[cfg(feature = "hyper-client")]
pub struct HttpsConnector {
    http: HttpConnector,
    tls: TlsConnector,
}

#[cfg(feature = "hyper-client")]
impl HttpsConnector {
    /// Build a connector using a default [`HttpConnector`] for the TCP
    /// step. `enforce_http(false)` is set so the inner connector
    /// accepts the non-`http` scheme on the way through.
    #[must_use]
    pub fn new(tls: TlsConnector) -> Self {
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        Self { http, tls }
    }

    /// Build a connector from a pre-configured [`HttpConnector`]. The
    /// caller sets `enforce_http(false)`; this constructor leaves the
    /// supplied connector as is.
    #[must_use]
    pub fn with_http_connector(http: HttpConnector, tls: TlsConnector) -> Self {
        Self { http, tls }
    }

    /// Borrow the wrapped [`TlsConnector`].
    #[must_use]
    pub fn tls(&self) -> &TlsConnector {
        &self.tls
    }

    /// Borrow the wrapped [`HttpConnector`].
    #[must_use]
    pub fn http(&self) -> &HttpConnector {
        &self.http
    }
}

#[cfg(feature = "hyper-client")]
impl From<TlsConnector> for HttpsConnector {
    fn from(tls: TlsConnector) -> Self {
        Self::new(tls)
    }
}

#[cfg(feature = "hyper-client")]
type ConnFuture = Pin<Box<dyn Future<Output = io::Result<TokioIo<TlsStream>>> + Send>>;

#[cfg(feature = "hyper-client")]
impl Service<Uri> for HttpsConnector {
    type Response = TokioIo<TlsStream>;
    type Error = io::Error;
    type Future = ConnFuture;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Service::<Uri>::poll_ready(&mut self.http, cx).map_err(io::Error::other)
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let scheme = uri.scheme_str().map(str::to_owned);
        let host = uri.host().map(str::to_owned);
        let mut http = self.http.clone();
        let tls = self.tls.clone();

        Box::pin(async move {
            if scheme.as_deref() != Some("https") {
                return Err(io::Error::other(format!(
                    "HttpsConnector requires https://; got scheme {scheme:?}"
                )));
            }
            let host = host.ok_or_else(|| io::Error::other("URI is missing a host"))?;
            // Uri::host() retains IPv6 brackets, but TlsConnector expects
            // a bare IP literal to select IP-SAN verification and omit SNI.
            let host = host
                .strip_prefix('[')
                .and_then(|host| host.strip_suffix(']'))
                .unwrap_or(&host);

            // TCP step via hyper-util's HttpConnector, then unwrap back
            // to a plain TcpStream for our connector.
            let tcp_io = Service::<Uri>::call(&mut http, uri)
                .await
                .map_err(io::Error::other)?;
            let tcp = tcp_io.into_inner();

            // TLS step.
            let tls_stream = tls.connect(host, tcp).await.map_err(io::Error::other)?;
            Ok(TokioIo::new(tls_stream))
        })
    }
}

// Implementing `Connection` for `TlsStream` lets the blanket
// `impl<T: Connection> Connection for TokioIo<T>` in hyper-util make
// our `TokioIo<TlsStream>` response usable as a hyper client
// connection (so `Client::builder().build(https)` accepts us).
#[cfg(feature = "hyper-client")]
impl Connection for TlsStream {
    fn connected(&self) -> Connected {
        let info = Connected::new();
        if self.negotiated().alpn().is_some_and(|a| a == b"h2") {
            info.negotiated_h2()
        } else {
            info
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[cfg(feature = "hyper-client")]
    use crate::ClientConfig;
    #[cfg(feature = "hyper-server")]
    use crate::ServerConfig;

    const TEST_CERT_PEM: &[u8] = include_bytes!("../tests/data/cert.pem");
    #[cfg(feature = "hyper-server")]
    const TEST_KEY_PEM: &[u8] = include_bytes!("../tests/data/key.pem");

    #[cfg(feature = "hyper-server")]
    fn test_acceptor() -> TlsAcceptor {
        let cfg = Arc::new(
            ServerConfig::builder()
                .with_pem_bytes(TEST_CERT_PEM, TEST_KEY_PEM)
                .expect("ServerConfig builds"),
        );
        TlsAcceptor::new(cfg)
    }

    #[cfg(feature = "hyper-client")]
    fn test_connector() -> TlsConnector {
        let cfg = Arc::new(
            ClientConfig::builder()
                .with_root_certs_pem_bytes(TEST_CERT_PEM)
                .build()
                .expect("ClientConfig builds"),
        );
        TlsConnector::new(cfg)
    }

    #[test]
    #[cfg(feature = "hyper-server")]
    fn hyper_acceptor_from_and_inner() {
        let a = test_acceptor();
        let h: HyperAcceptor = a.into();
        // `inner()` returns the wrapped TlsAcceptor; the Clone impl
        // means it's cheap to bounce a reference back out for chaining.
        let _: TlsAcceptor = h.inner().clone();
        // Clone the wrapper itself.
        let _ = h.clone();
    }

    #[test]
    #[cfg(feature = "hyper-client")]
    fn https_connector_default_constructor() {
        let c = HttpsConnector::new(test_connector());
        // Both getters should hand back live references.
        let _: &TlsConnector = c.tls();
        let _: &HttpConnector = c.http();
        let _ = c.clone();
    }

    #[test]
    #[cfg(feature = "hyper-client")]
    fn https_connector_with_custom_http_connector() {
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        let c = HttpsConnector::with_http_connector(http, test_connector());
        let _: &HttpConnector = c.http();
    }
}
