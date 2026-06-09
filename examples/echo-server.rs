//! TLS echo server built on [`TlsAcceptor`].
//!
//! Accepts each connection, reads bytes until the peer closes the write
//! half, and echoes them back. Each connection is handled in its own
//! Tokio task.
//!
//! Run with the bundled test fixtures:
//!
//! ```sh
//! cargo run --example echo-server -- 127.0.0.1:8443 \
//!     tests/data/cert.pem tests/data/key.pem
//! ```
//!
//! Then talk to it from another terminal:
//!
//! ```sh
//! openssl s_client -connect 127.0.0.1:8443 -servername localhost \
//!     -CAfile tests/data/cert.pem -quiet
//! ```

use std::env;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_aws_lc::{ServerConfig, TlsAcceptor};

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
            .alpn_protocols(&[b"echo/1"])
            .with_pem_files(&cert, &key)?,
    );
    let acceptor = TlsAcceptor::new(cfg);

    let listener = TcpListener::bind(&bind).await?;
    eprintln!("echo-server listening on {bind}");

    loop {
        let (tcp, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            match acceptor.accept(tcp).await {
                Ok(mut tls) => {
                    let neg = tls.negotiated();
                    eprintln!(
                        "{peer}: handshake ok ({} / {}, alpn={:?})",
                        neg.version(),
                        neg.cipher(),
                        neg.alpn().map(String::from_utf8_lossy),
                    );
                    if let Err(e) = echo(&mut tls).await {
                        eprintln!("{peer}: io error: {e}");
                    }
                    let _ = tls.shutdown().await;
                }
                Err(e) => eprintln!("{peer}: handshake failed: {e}"),
            }
        });
    }
}

async fn echo<S>(stream: &mut S) -> std::io::Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut buf = [0u8; 4096];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        stream.write_all(&buf[..n]).await?;
    }
}
