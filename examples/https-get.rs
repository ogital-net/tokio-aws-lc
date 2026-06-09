//! Minimal HTTPS client built on [`TlsConnector`].
//!
//! Performs a raw HTTP/1.1 `GET /` against a host (default `example.com`)
//! and prints the response. Verification uses the system trust store by
//! default; pass `--ca <pem>` to pin a specific bundle (useful when
//! pointing at a development server with a self-signed cert).
//!
//! ```sh
//! cargo run --example https-get -- example.com 443
//! cargo run --example https-get -- localhost 8443 --ca tests/data/cert.pem
//! ```

use std::env;
use std::fs;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_aws_lc::{ClientConfig, TlsConnector};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let host: String = args.next().unwrap_or_else(|| "example.com".into());
    let port: u16 = args
        .next()
        .as_deref()
        .map_or(Ok(443), str::parse)
        .unwrap_or(443);

    let mut ca: Option<Vec<u8>> = None;
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--ca" => {
                let path = args.next().ok_or("--ca requires a path argument")?;
                ca = Some(fs::read(path)?);
            }
            other => return Err(format!("unknown argument: {other}").into()),
        }
    }

    let mut builder = ClientConfig::builder().alpn_protocols(&[b"http/1.1"]);
    builder = if let Some(pem) = &ca {
        builder.with_root_certs_pem_bytes(pem)
    } else {
        builder.with_system_root_certs()
    };
    let cfg = Arc::new(builder.build()?);
    let connector = TlsConnector::new(cfg);

    let tcp = TcpStream::connect((host.as_str(), port)).await?;
    let mut tls = connector.connect(&host, tcp).await?;

    let neg = tls.negotiated();
    eprintln!(
        "connected: {} / {} (alpn={:?})",
        neg.version(),
        neg.cipher(),
        neg.alpn().map(String::from_utf8_lossy),
    );

    let req = format!(
        "GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: tokio-aws-lc-example/0.1\r\n\r\n"
    );
    tls.write_all(req.as_bytes()).await?;

    let mut body = Vec::with_capacity(4096);
    tls.read_to_end(&mut body).await?;
    let _ = tls.shutdown().await;

    println!("{}", String::from_utf8_lossy(&body));
    Ok(())
}
