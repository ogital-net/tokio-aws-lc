//! DER parsing helpers shared by the server and client config builders.
//!
//! These wrap the `d2i_*` family in AWS-LC's libcrypto and return
//! freshly-owned pointers. The caller is responsible for freeing the
//! returned object (typically via `X509_free` / `EVP_PKEY_free`, or by
//! handing ownership off to an `SSL_CTX_*` setter that bumps the
//! refcount and leaving us to drop our local reference).

use std::os::raw::c_long;
use std::ptr;

use crate::error::{last_error, Error, Result};

/// DER-decode a single X.509 certificate. Returns a freshly-owned
/// `*mut X509`; the caller must `X509_free` it (or transfer ownership).
pub(super) fn parse_x509(der: &[u8]) -> Result<*mut aws_lc_sys::X509> {
    if der.is_empty() {
        return Err(Error::Init(
            "DER-encoded certificate must not be empty".into(),
        ));
    }
    let len = c_long::try_from(der.len()).map_err(|_| {
        Error::Init("DER-encoded certificate exceeds the maximum supported length".into())
    })?;
    let mut p = der.as_ptr();
    // SAFETY: `&mut p` is a writable pointer-to-pointer (d2i_X509
    // advances it past the parsed object); `len` matches the readable
    // length of the input slice. Passing `out = null` requests a fresh
    // allocation.
    let cert = unsafe { aws_lc_sys::d2i_X509(ptr::null_mut(), ptr::from_mut(&mut p), len) };
    if cert.is_null() {
        return Err(Error::Init(format!("d2i_X509: {}", last_error())));
    }
    Ok(cert)
}

/// DER-decode an `EVP_PKEY` from any of the formats AWS-LC's
/// auto-detector accepts (PKCS#8, PKCS#1 RSA, SEC1 EC). Returns a
/// freshly-owned `*mut EVP_PKEY`; the caller must `EVP_PKEY_free` it
/// (or transfer ownership).
pub(super) fn parse_private_key(der: &[u8]) -> Result<*mut aws_lc_sys::EVP_PKEY> {
    if der.is_empty() {
        return Err(Error::Init(
            "DER-encoded private key must not be empty".into(),
        ));
    }
    let len = c_long::try_from(der.len()).map_err(|_| {
        Error::Init("DER-encoded private key exceeds the maximum supported length".into())
    })?;
    let mut p = der.as_ptr();
    // SAFETY: same contract as parse_x509; d2i_AutoPrivateKey infers
    // PKCS#8 vs the legacy SEC1/PKCS#1 wrappers.
    let key =
        unsafe { aws_lc_sys::d2i_AutoPrivateKey(ptr::null_mut(), ptr::from_mut(&mut p), len) };
    if key.is_null() {
        return Err(Error::Init(format!("d2i_AutoPrivateKey: {}", last_error())));
    }
    Ok(key)
}
