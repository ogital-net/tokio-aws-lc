//! Steady-state throughput: bytes/sec moved over an already-established
//! TLS connection. The handshake is excluded from the timed region via
//! `iter_custom` so the numbers reflect the record-layer cost alone.
//!
//! Backends:
//!
//! - `tokio_aws_lc/userspace` — both sides `disable_ktls()`. Data
//!   path: `SSL_write` → `BIO_write` → `send(2)`.
//! - `tokio_aws_lc/ktls` — auto-install on Linux after the
//!   handshake. Data path: `write(2)` on the `tls` ULP'd socket;
//!   AEAD happens in the kernel. On non-Linux this falls through to
//!   the userspace path (auto-install silently no-ops), so the row is
//!   skipped to keep the comparison honest.
//! - `rustls_aws_lc_rs` — `tokio-rustls` with rustls's `aws-lc-rs`
//!   crypto provider.
//!
//! Payload size: 1 MiB per iteration. Reported as MiB/s via
//! `Throughput::Bytes`.

mod common;

use std::time::{Duration, Instant};

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use tokio::io::AsyncWriteExt as _;

use common::{
    build_runtime, spawn_awslc_server, spawn_rustls_server, tcp_connect, AwsLcStack, RustlsStack,
};

const PAYLOAD_LEN: usize = 1024 * 1024;

fn bench_throughput(c: &mut Criterion) {
    let rt = build_runtime();
    let payload: Vec<u8> = (0..PAYLOAD_LEN)
        .map(|i| u8::try_from(i & 0xff).unwrap())
        .collect();

    let mut group = c.benchmark_group("throughput_1MiB");
    group.throughput(Throughput::Bytes(PAYLOAD_LEN as u64));
    group.sample_size(40);

    // tokio-aws-lc userspace
    {
        let stack = AwsLcStack::new(/*userspace=*/ true);
        let server = rt.block_on(spawn_awslc_server(stack.acceptor.clone(), true));
        let connector = stack.connector.clone();
        let port = server.port;
        let payload = payload.clone();
        group.bench_function("tokio_aws_lc_userspace", |b| {
            b.to_async(&rt).iter_custom(|iters| {
                let connector = connector.clone();
                let payload = payload.clone();
                async move {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let tcp = tcp_connect(port).await;
                        let mut stream = connector
                            .connect("localhost", tcp)
                            .await
                            .expect("client handshake");
                        let start = Instant::now();
                        stream.write_all(&payload).await.expect("write_all");
                        stream.shutdown().await.ok();
                        total += start.elapsed();
                    }
                    total
                }
            });
        });
    }

    // tokio-aws-lc kTLS (Linux-only effective path)
    #[cfg(target_os = "linux")]
    {
        let stack = AwsLcStack::new(/*userspace=*/ false);
        let server = rt.block_on(spawn_awslc_server(stack.acceptor.clone(), true));
        let connector = stack.connector.clone();
        let port = server.port;
        let payload = payload.clone();
        group.bench_function("tokio_aws_lc_ktls", |b| {
            b.to_async(&rt).iter_custom(|iters| {
                let connector = connector.clone();
                let payload = payload.clone();
                async move {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let tcp = tcp_connect(port).await;
                        let mut stream = connector
                            .connect("localhost", tcp)
                            .await
                            .expect("client handshake");
                        // If the auto-install silently fell back to
                        // userspace (host kernel without the `tls`
                        // module, etc.) we still time it — the bench
                        // will then read as equal to the userspace
                        // row, which is the truthful answer for this
                        // host.
                        let start = Instant::now();
                        stream.write_all(&payload).await.expect("write_all");
                        stream.shutdown().await.ok();
                        total += start.elapsed();
                    }
                    total
                }
            });
        });
    }

    // tokio-rustls (aws-lc-rs provider)
    {
        let stack = RustlsStack::new();
        let server = rt.block_on(spawn_rustls_server(stack.acceptor.clone(), true));
        let connector = stack.connector.clone();
        let port = server.port;
        let payload = payload.clone();
        let server_name = tokio_rustls::rustls::pki_types::ServerName::try_from("localhost")
            .expect("server name");
        group.bench_function("rustls_aws_lc_rs", |b| {
            b.to_async(&rt).iter_custom(|iters| {
                let connector = connector.clone();
                let payload = payload.clone();
                let server_name = server_name.clone();
                async move {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let tcp = tcp_connect(port).await;
                        let mut stream = connector
                            .connect(server_name.clone(), tcp)
                            .await
                            .expect("client handshake");
                        let start = Instant::now();
                        stream.write_all(&payload).await.expect("write_all");
                        stream.shutdown().await.ok();
                        total += start.elapsed();
                    }
                    total
                }
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_throughput);
criterion_main!(benches);
