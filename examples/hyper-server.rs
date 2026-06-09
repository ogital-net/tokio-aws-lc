//! HTTPS server built on the [`hyper`](https://docs.rs/hyper) integration.
//!
//! Wraps [`TlsAcceptor`] in a [`HyperAcceptor`] and serves a single
//! "hello" response via `hyper_util`'s auto-negotiating connection
//! builder. ALPN advertises both HTTP/1.1 and HTTP/2; the negotiated
//! protocol is picked by the client.
//!
//! Requires the `hyper` feature:
//!
//! ```sh
//! cargo run --example hyper-server --features hyper -- \
//!     127.0.0.1:8443 tests/data/cert.pem tests/data/key.pem
//! ```
//!
//! Try it with `curl`:
//!
//! ```sh
//! curl --cacert tests/data/cert.pem --resolve localhost:8443:127.0.0.1 \
//!     https://localhost:8443/
//! curl --http2 --cacert tests/data/cert.pem \
//!     --resolve localhost:8443:127.0.0.1 https://localhost:8443/
//! ```

use std::convert::Infallible;
use std::env;
use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioExecutor;
use hyper_util::server::conn::auto;
use tokio::net::TcpListener;
use tokio_aws_lc::hyper::HyperAcceptor;
use tokio_aws_lc::{ServerConfig, TlsAcceptor};

async fn hello(req: Request<hyper::body::Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let body = format!("hello {} {}\n", req.method(), req.uri().path());
    Ok(Response::new(Full::new(Bytes::from(body))))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let bind: String = args.next().unwrap_or_else(|| "127.0.0.1:8443".into());
    let cert: PathBuf = args
        .next()
        .map_or_else(|| PathBuf::from("tests/data/cert.pem"), PathBuf::from);
    let key: PathBuf = args
        .next()
        .map_or_else(|| PathBuf::from("tests/data/key.pem"), PathBuf::from);

    let cfg = Arc::new(
        ServerConfig::builder()
            .alpn_protocols(&[b"h2", b"http/1.1"])
            .with_pem_files(&cert, &key)?,
    );
    let acceptor = HyperAcceptor::new(TlsAcceptor::new(cfg));

    let listener = TcpListener::bind(&bind).await?;
    eprintln!("hyper-server listening on https://{bind}");

    loop {
        let (tcp, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let io = match acceptor.accept(tcp).await {
                Ok(io) => io,
                Err(e) => {
                    eprintln!("{peer}: handshake failed: {e}");
                    return;
                }
            };
            if let Err(e) = auto::Builder::new(TokioExecutor::new())
                .serve_connection(io, service_fn(hello))
                .await
            {
                eprintln!("{peer}: hyper error: {e}");
            }
        });
    }
}
