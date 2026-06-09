//! Handshake throughput: how many full TCP + TLS handshakes per second
//! can a single client drive against an in-process server on loopback.
//!
//! Three backends:
//!
//! - `tokio_aws_lc_userspace` — this crate with `disable_ktls()` on
//!   both sides, so `accept`/`connect` skip the kTLS install probe
//!   entirely. Lower bound for our handshake cost.
//! - `tokio_aws_lc_auto_ktls` — this crate with the default config,
//!   so `accept`/`connect` run the kTLS auto-install path on
//!   handshake completion. On a host with the `tls` ULP loaded this
//!   succeeds and bumps the data path into the kernel; on a host
//!   without it (e.g. after `rmmod tls`) the install fails fast with
//!   `TlsUlpUnavailable` and the stream silently falls back to
//!   userspace AEAD. Comparing this row against the userspace row
//!   measures the auto-install overhead, both in the success case
//!   and in the fallback case.
//! - `rustls_aws_lc_rs` — `tokio-rustls` with rustls's `aws-lc-rs`
//!   crypto provider. Same underlying `libcrypto` as us.
//!
//! Each iteration:
//!   1. Open a TCP connection (`set_nodelay(true)`).
//!   2. Run the client-side handshake to completion.
//!   3. Drop the stream (sending `close_notify` + FIN).
//!
//! The server task accepts in a loop and runs the server-side
//! handshake on each connection. No application data is exchanged.

mod common;

use criterion::{criterion_group, criterion_main, Criterion};

use common::{
    build_runtime, spawn_awslc_server, spawn_rustls_server, tcp_connect, AwsLcStack, RustlsStack,
};

fn bench_handshake(c: &mut Criterion) {
    let rt = build_runtime();
    let mut group = c.benchmark_group("handshake");
    group.sample_size(60);

    // tokio-aws-lc, kTLS auto-install disabled
    {
        let stack = AwsLcStack::new(/*userspace=*/ true);
        let server = rt.block_on(spawn_awslc_server(stack.acceptor.clone(), false));
        let connector = stack.connector.clone();
        let port = server.port;
        group.bench_function("tokio_aws_lc_userspace", |b| {
            b.to_async(&rt).iter(|| {
                let connector = connector.clone();
                async move {
                    let tcp = tcp_connect(port).await;
                    let stream = connector
                        .connect("localhost", tcp)
                        .await
                        .expect("client handshake");
                    drop(stream);
                }
            });
        });
    }

    // tokio-aws-lc, kTLS auto-install on (success or silent fallback
    // depending on whether the host kernel exposes the `tls` ULP).
    {
        let stack = AwsLcStack::new(/*userspace=*/ false);
        let server = rt.block_on(spawn_awslc_server(stack.acceptor.clone(), false));
        let connector = stack.connector.clone();
        let port = server.port;
        group.bench_function("tokio_aws_lc_auto_ktls", |b| {
            b.to_async(&rt).iter(|| {
                let connector = connector.clone();
                async move {
                    let tcp = tcp_connect(port).await;
                    let stream = connector
                        .connect("localhost", tcp)
                        .await
                        .expect("client handshake");
                    drop(stream);
                }
            });
        });
    }

    // tokio-rustls (aws-lc-rs provider)
    {
        let stack = RustlsStack::new();
        let server = rt.block_on(spawn_rustls_server(stack.acceptor.clone(), false));
        let connector = stack.connector.clone();
        let port = server.port;
        let server_name = tokio_rustls::rustls::pki_types::ServerName::try_from("localhost")
            .expect("server name");
        group.bench_function("rustls_aws_lc_rs", |b| {
            b.to_async(&rt).iter(|| {
                let connector = connector.clone();
                let server_name = server_name.clone();
                async move {
                    let tcp = tcp_connect(port).await;
                    let stream = connector
                        .connect(server_name, tcp)
                        .await
                        .expect("client handshake");
                    drop(stream);
                }
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_handshake);
criterion_main!(benches);
