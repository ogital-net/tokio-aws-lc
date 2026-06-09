//! Read-only view onto a negotiated TLS session.

use std::ffi::CStr;
use std::os::raw::{c_char, c_int};

use crate::error::{last_error, Error, Result};
use crate::ffi::Ssl;
use crate::ktls::cipher::KtlsCipher;

/// Whether the current TLS session can be offloaded to the Linux
/// `tls` ULP (kernel TLS). Returned by [`crate::TlsStream::ktls_eligibility`].
///
/// All fields are diagnostic only — the kTLS dispatch under the hood
/// uses the integer cipher-suite ID, not these strings.
#[derive(Debug, Clone)]
pub struct KtlsEligibility {
    tls_version: String,
    cipher: String,
    compatible: bool,
}

impl KtlsEligibility {
    /// Negotiated TLS version as reported by AWS-LC
    /// (`"TLSv1.2"`, `"TLSv1.3"`, or `"(unknown)"`).
    #[must_use]
    pub fn tls_version(&self) -> &str {
        &self.tls_version
    }

    /// AWS-LC cipher name (e.g. `"TLS_AES_128_GCM_SHA256"` or
    /// `"ECDHE-ECDSA-AES128-GCM-SHA256"`). Empty if
    /// `SSL_get_current_cipher` returned null.
    #[must_use]
    pub fn cipher(&self) -> &str {
        &self.cipher
    }

    /// `true` if the (version, cipher) tuple is one the kernel `tls`
    /// ULP can offload. Does not check the host kernel — eligibility
    /// here is a structural property of the negotiation only.
    #[must_use]
    pub fn is_compatible(&self) -> bool {
        self.compatible
    }

    /// Snapshot from a live SSL handle.
    ///
    /// # Safety
    ///
    /// `ssl` must point to a live SSL handle whose handshake has completed.
    pub(crate) unsafe fn from_ssl(ssl: &Ssl) -> Self {
        // SAFETY: ssl is live per caller contract.
        let tls_version = unsafe { cstr_to_string(aws_lc_sys::SSL_get_version(ssl.as_ptr())) }
            .unwrap_or_else(|| "(unknown)".into());
        // SAFETY: ssl is live; SSL_get_current_cipher returns a borrowed
        // SSL_CIPHER pointer or null.
        let cipher_ptr = unsafe { aws_lc_sys::SSL_get_current_cipher(ssl.as_ptr()) };
        let cipher = if cipher_ptr.is_null() {
            String::new()
        } else {
            // SAFETY: cipher_ptr is live; SSL_CIPHER_get_name returns a
            // static-lifetime string.
            unsafe { cstr_to_string(aws_lc_sys::SSL_CIPHER_get_name(cipher_ptr)) }
                .unwrap_or_default()
        };
        Self {
            tls_version,
            cipher,
            compatible: KtlsCipher::detect(ssl).is_some(),
        }
    }
}

/// Negotiated parameters of an established session.
///
/// Snapshot of what the handshake settled on: protocol version, cipher
/// suite name, ALPN selection (if any), and SNI (server side only).
/// Cheap to construct; obtained via [`crate::TlsStream::negotiated`].
#[derive(Debug, Clone)]
pub struct NegotiatedSession {
    version: String,
    cipher: String,
    alpn: Option<Vec<u8>>,
    sni: Option<String>,
}

impl NegotiatedSession {
    /// Negotiated TLS protocol version (e.g. `"TLSv1.3"`, `"TLSv1.2"`).
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Negotiated cipher-suite name as reported by AWS-LC
    /// (e.g. `"TLS_AES_128_GCM_SHA256"`). Empty if no cipher has been
    /// established (shouldn't happen post-handshake, but the FFI returns
    /// null in that case).
    #[must_use]
    pub fn cipher(&self) -> &str {
        &self.cipher
    }

    /// Negotiated ALPN protocol, if the handshake selected one.
    #[must_use]
    pub fn alpn(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
    }

    /// SNI value sent by the client, if any. Always `None` on the client
    /// side.
    #[must_use]
    pub fn sni(&self) -> Option<&str> {
        self.sni.as_deref()
    }

    /// Snapshot the current SSL state.
    ///
    /// # Safety
    ///
    /// `ssl` must point to a live SSL handle whose handshake has completed.
    pub(crate) unsafe fn from_ssl(ssl: *mut aws_lc_sys::SSL) -> Self {
        // SAFETY: ssl is live per caller contract; SSL_get_version returns
        // a static string.
        let version = unsafe { cstr_to_string(aws_lc_sys::SSL_get_version(ssl)) }
            .unwrap_or_else(|| "(unknown)".into());

        // SAFETY: ssl is live; SSL_get_current_cipher returns a borrowed
        // SSL_CIPHER pointer or null.
        let cipher_ptr = unsafe { aws_lc_sys::SSL_get_current_cipher(ssl) };
        let cipher = if cipher_ptr.is_null() {
            String::new()
        } else {
            // SAFETY: cipher_ptr is live; SSL_CIPHER_get_name returns a
            // static string.
            unsafe { cstr_to_string(aws_lc_sys::SSL_CIPHER_get_name(cipher_ptr)) }
                .unwrap_or_default()
        };

        // ALPN: SSL_get0_alpn_selected returns a borrowed slice into the
        // SSL's internal state. We copy it out so the snapshot has its
        // own lifetime.
        let mut alpn_ptr: *const u8 = std::ptr::null();
        let mut alpn_len: u32 = 0;
        // SAFETY: ssl is live; both out-params are valid.
        unsafe {
            aws_lc_sys::SSL_get0_alpn_selected(ssl, &raw mut alpn_ptr, &raw mut alpn_len);
        }
        let alpn = if alpn_ptr.is_null() || alpn_len == 0 {
            None
        } else {
            // SAFETY: AWS-LC guarantees the returned slice is valid for
            // the lifetime of the SSL handle; we copy before that ends.
            let slice = unsafe { std::slice::from_raw_parts(alpn_ptr, alpn_len as usize) };
            Some(slice.to_vec())
        };

        // SNI (server side): SSL_get_servername with TLSEXT_NAMETYPE_host_name.
        // Returns null on the client side or when the client sent no SNI.
        // SAFETY: ssl is live; the type constant is a scalar.
        let sni_ptr = unsafe {
            aws_lc_sys::SSL_get_servername(ssl, aws_lc_sys::TLSEXT_NAMETYPE_host_name as c_int)
        };
        let sni = if sni_ptr.is_null() {
            None
        } else {
            // SAFETY: sni_ptr is live for the lifetime of the SSL handle;
            // we copy before that ends.
            unsafe { cstr_to_string(sni_ptr) }
        };

        Self {
            version,
            cipher,
            alpn,
            sni,
        }
    }
}

/// Borrow a `*const c_char` as a `String`, returning None on null.
unsafe fn cstr_to_string(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    // SAFETY: caller guarantees `p` points to a NUL-terminated string.
    let s = unsafe { CStr::from_ptr(p) };
    Some(s.to_string_lossy().into_owned())
}

/// RFC 5705 keying-material exporter, wrapped for safe call from
/// [`crate::TlsStream::export_keying_material`].
///
/// # Safety
///
/// `ssl` must point to a live SSL handle whose handshake has completed.
pub(crate) unsafe fn export_keying_material(
    ssl: *mut aws_lc_sys::SSL,
    out: &mut [u8],
    label: &[u8],
    context: Option<&[u8]>,
) -> Result<()> {
    let (ctx_ptr, ctx_len, use_ctx) = match context {
        Some(c) => (c.as_ptr(), c.len(), 1),
        None => (std::ptr::null(), 0usize, 0),
    };
    // SAFETY: out/label/context buffers are valid for the call; ssl is
    // live per caller contract.
    let ok = unsafe {
        aws_lc_sys::SSL_export_keying_material(
            ssl,
            out.as_mut_ptr(),
            out.len(),
            label.as_ptr().cast(),
            label.len(),
            ctx_ptr,
            ctx_len,
            use_ctx,
        )
    };
    if ok == 1 {
        Ok(())
    } else {
        Err(Error::Handshake(format!(
            "SSL_export_keying_material: {}",
            last_error()
        )))
    }
}
