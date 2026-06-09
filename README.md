# tokio-aws-lc

[![crates.io](https://img.shields.io/crates/v/tokio-aws-lc.svg)](https://crates.io/crates/tokio-aws-lc)
[![docs.rs](https://docs.rs/tokio-aws-lc/badge.svg)](https://docs.rs/tokio-aws-lc)
[![license](https://img.shields.io/crates/l/tokio-aws-lc.svg)](https://github.com/ogital-net/tokio-aws-lc/blob/main/LICENSE)

Async TLS for Tokio on top of [`aws-lc-sys`](https://crates.io/crates/aws-lc-sys),
with built-in Linux kTLS install for AEAD sessions.

## Why this crate

`tokio-rustls` over rustls's `aws-lc-rs` provider is the right default
for most workloads. `tokio-aws-lc` exists for two cases it doesn't
cover:

- **kTLS without manual plumbing.** The kernel's `tls` ULP turns
  per-record AEAD into a `read(2)` / `write(2)`, dropping a userspace
  copy and the AEAD CPU on bulk transfers. Wiring it against rustls
  means reaching past the public API to extract the negotiated
  traffic keys and calling `setsockopt(SOL_TLS, ...)` by hand. This
  crate installs both directions on `accept` / `connect` completion
  whenever the negotiated cipher is one the kernel understands, and
  the data path flips to `read(2)` / `write(2)` automatically.
- **A single AWS-LC.** A codebase that already links `aws-lc-sys`
  (FIPS deployments, hand-rolled EC code, shared X.509 handling)
  otherwise pulls two near-identical libcryptos once it also depends
  on rustls's `aws-lc-rs` provider. This crate keeps it to one.

If neither matters, prefer `tokio-rustls`.

## How this crate uses AWS-LC vs how rustls does

The two stacks pull very different surface area from the same upstream
project, and it's easy to assume "rustls + `aws-lc-rs`" means rustls is
using AWS-LC's TLS engine. It is not.

- **rustls + `aws-lc-rs` provider** uses AWS-LC only as a crypto
  library: AEAD primitives (AES-GCM, ChaCha20-Poly1305), HKDF,
  signature verification (RSA, ECDSA, `EdDSA`), key exchange (X25519,
  the NIST P-curves, the hybrid PQ groups), and the TLS 1.2 PRF.
  Everything else — the TLS state machine, the record layer, the
  handshake, X.509 chain validation (via `webpki`), SNI, ALPN,
  session tickets — is rustls's own pure-Rust code. `aws-lc-rs`
  exposes a ring-compatible API on top of `aws-lc-sys` so rustls can
  swap providers; nothing in `libssl` is reachable from there.
- **`tokio-aws-lc`** uses AWS-LC's `libssl`. The TLS state machine,
  record layer, handshake, X.509 chain validation, SNI matching, and
  ALPN selection all live in AWS-LC; this crate is a Tokio adapter
  layered on `SSL_CTX` / `SSL` / `BIO`. The `ServerConfig` and
  `ClientConfig` builders are thin wrappers that translate typed
  configuration into `SSL_CTX_set_*` calls.

That difference is what makes the kTLS path tractable here:
extracting the post-handshake traffic keys and sequence numbers is a
sequence of `SSL_*` getters in `libssl`, and there's nowhere in
rustls's public API to reach them without forking. It is also why
behavior around things like client-cert verification, IP-SAN
matching, and protocol-version selection follows AWS-LC's
conventions rather than rustls's — the builder API hides the FFI but
not the semantics.

## Status

Pre-release (`0.1.0`).

| Surface | State |
| --- | --- |
| Server (`TlsAcceptor`, `ServerConfig`) | Round-trip tested against `openssl s_client` and against this crate's client. |
| Client (`TlsConnector`, `ClientConfig`) | PEM / system trust roots, SNI, IP-SAN, mTLS, ALPN. |
| Linux kTLS (`TLS_TX` + `TLS_RX`) | TLS 1.3 (AES-128/256-GCM, ChaCha20-Poly1305) and TLS 1.2 AEAD; integration-tested via `/proc/net/tls_stat`. |
| Optional `hyper` integration | Server acceptor + `tower::Service<Uri>` client connector for `hyper` 1.x. |

Not in `0.1`: session resumption, `UnixStream`, BIO-pair fallback for
arbitrary IO, post-attach TLS 1.3 `KeyUpdate`, `tracing` instrumentation,
Windows.

## Install

```toml
[dependencies]
tokio-aws-lc = "0.1"
```

The default build pulls only `aws-lc-sys` and `tokio`. The `hyper`
adapters are opt-in:

```toml
tokio-aws-lc = { version = "0.1", features = ["hyper"] }
```

Build prerequisites are whatever `aws-lc-sys` itself needs: `cmake`,
`clang`, `libclang-dev`, `perl`, plus a working C toolchain.

## Quick start

### Server

```rust,no_run
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio_aws_lc::{ServerConfig, TlsAcceptor};

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let cfg = Arc::new(
    ServerConfig::builder()
        .alpn_protocols(&[b"h2", b"http/1.1"])
        .with_pem_files("cert.pem".as_ref(), "key.pem".as_ref())?,
);
let acceptor = TlsAcceptor::new(cfg);

let listener = TcpListener::bind("0.0.0.0:8443").await?;
loop {
    let (tcp, _peer) = listener.accept().await?;
    let acceptor = acceptor.clone();
    tokio::spawn(async move {
        let mut tls = acceptor.accept(tcp).await?;
        tls.write_all(b"hello\n").await?;
        tls.shutdown().await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });
}
# }
```

### Client

```rust,no_run
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_aws_lc::{ClientConfig, TlsConnector};

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let cfg = Arc::new(
    ClientConfig::builder()
        .with_system_root_certs()
        .alpn_protocols(&[b"http/1.1"])
        .build()?,
);
let connector = TlsConnector::new(cfg);

let tcp = TcpStream::connect(("example.com", 443)).await?;
let mut tls = connector.connect("example.com", tcp).await?;
tls.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
    .await?;
let mut body = Vec::new();
tls.read_to_end(&mut body).await?;
# Ok(())
# }
```

`TlsConnector::connect` accepts both DNS names and IP literals. DNS
names go out as the SNI extension and are matched against the
certificate's DNS SANs / CN; IP literals skip SNI (RFC 6066 §3) and
are matched against the certificate's iPAddress SANs.

## Linux kTLS

When the negotiated session is kTLS-eligible (TLS 1.2 or 1.3 with
AES-GCM or ChaCha20-Poly1305), the kernel `tls` ULP is attached to
the TCP socket and the negotiated AEAD keys are uploaded for both
directions. After that, `AsyncRead` / `AsyncWrite` move plaintext
through `read(2)` / `write(2)` and the kernel runs the AEAD record
layer.

Install happens automatically when `TlsAcceptor::accept` /
`TlsConnector::connect` resolves. Hosts that can't take the install
— non-Linux, kernels without `CONFIG_TLS`, the module not loaded,
sessions with an ineligible cipher — stay on the userspace AEAD path
without surfacing an error. Inspect `TlsStream::ktls_active()` after
the handshake to confirm.

The probe is cheap (`SSL_pending` + one or three `setsockopt` calls,
on the order of a microsecond on loopback) so it's safe to leave on.
To skip it entirely, call `disable_ktls()` on the builder:

```rust,no_run
use tokio_aws_lc::ServerConfig;

# fn _build() -> Result<(), Box<dyn std::error::Error>> {
let cfg = ServerConfig::builder()
    .disable_ktls()
    .with_pem_files("cert.pem".as_ref(), "key.pem".as_ref())?;
# Ok(())
# }
```

That's worth doing when you statically know the environment can't use
kTLS (locked-down containers without the module) or when you need
long-lived sessions where TLS 1.3 `KeyUpdate` may eventually fire.

`tokio_aws_lc::host_ktls_available()` is a startup probe that checks
for `/proc/net/tls_stat`, so consumers can branch on host support
without touching a real session.

Host prerequisites:

- Kernel ≥ 5.1 for TLS 1.3 (AES-GCM TX is 4.13+, AES-GCM RX is 4.17+,
  ChaCha20-Poly1305 is 5.11+).
- `tls` module loaded (`sudo modprobe tls`, or add `tls` to
  `/etc/modules-load.d/`). Inside containers, the host kernel must
  provide it.

### Re-key behavior

No userspace TLS stack handles a TLS 1.3 `KeyUpdate` after a kTLS
attach transparently: once the kernel owns the receive path, the
userspace engine never sees the post-handshake record, so it can't
rotate the kernel's keys. This crate currently lets the kernel
return `EIO` on any non-`application_data` record reaching the
socket, which surfaces as an IO error and tears the session down.
That is the strictest of the available options — `HAProxy` peeks at
`TLS_GET_RECORD_TYPE` via `recvmsg` cmsg to swallow
`NewSessionTicket` records and translate `close_notify` alerts into
EOF, but Tokio's `AsyncRead` has no cmsg surface to plumb that
through.

Callers that need long-lived sessions across rekeys should
`disable_ktls()` on those connections. Server-emitted post-handshake
records do not happen on this crate's server path: tickets are
disabled by construction (`SSL_OP_NO_TICKET` +
`SSL_CTX_set_num_tickets(0)`), and the crate never initiates a
`KeyUpdate` itself.

## Examples

```sh
# TLS echo server (uses the bundled test fixtures)
cargo run --example echo-server -- 127.0.0.1:8443 \
    tests/data/cert.pem tests/data/key.pem

# Minimal HTTPS client
cargo run --example https-get -- example.com 443

# Hyper 1.x server with HTTP/1.1 + HTTP/2 ALPN
cargo run --example hyper-server --features hyper -- \
    127.0.0.1:8443 tests/data/cert.pem tests/data/key.pem
```

## Cargo features

| Feature | Default | Description |
| --- | --- | --- |
| `hyper` | off | Server acceptor adapter and client `tower::Service<Uri>` connector for `hyper` 1.x via `hyper-util`. |

There is no parallel adapter for legacy `hyper` 0.14.

## Testing

```sh
cargo test                   # default features
cargo test --features hyper  # plus hyper integration tests
cargo test --no-default-features
```

The `server_roundtrip` integration test shells out to `openssl
s_client` and self-skips if `openssl` is not on `PATH`. The kTLS
tests skip themselves when `/proc/net/tls_stat` is unavailable or the
kernel rejects the per-direction crypto-info upload.

## MSRV

Rust 1.82 for the default build. The `hyper` feature transitively
pulls dependencies that track a newer rustc; consumers enabling it
must follow `hyper`'s MSRV.

## License

[BSD-2-Clause](https://github.com/ogital-net/tokio-aws-lc/blob/main/LICENSE).
