#![doc = include_str!("../README.md")]
#![doc(html_root_url = "https://docs.rs/tokio-aws-lc/0.1.0")]

pub mod acceptor;
pub mod config;
pub mod connector;
pub mod error;
mod ffi;
#[cfg(feature = "hyper")]
pub mod hyper;
mod ktls;
pub mod session;
pub mod stream;

pub use acceptor::TlsAcceptor;
pub use config::{
    cipher_suite, CipherSuite, ClientAuthMode, ClientConfig, ClientConfigBuilder, NamedGroup,
    ProtocolVersion, ServerConfig, ServerConfigBuilder,
};
pub use connector::TlsConnector;
pub use error::{Error, KtlsError, Result};
pub use ktls::host_ktls_available;
pub use session::{KtlsEligibility, NegotiatedSession};
pub use stream::TlsStream;
