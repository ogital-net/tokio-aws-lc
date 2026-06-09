//! Owning RAII wrappers around AWS-LC handles.
//!
//! Every wrapper holds a `NonNull<T>` pointer obtained from one of AWS-LC's
//! `*_new`-family constructors and frees it via the matching `*_free` in
//! its [`Drop`] impl. The wrappers are intentionally minimal — they own
//! the lifetime, expose `as_ptr()` for the FFI layer above them, and do
//! nothing else. Higher-level construction (`SSL_CTX_use_certificate_*`,
//! `SSL_set_fd`, etc.) lives in the modules that actually build a
//! `ServerConfig` or drive a `TlsStream`; keeping it out of here keeps the
//! `unsafe` surface here trivially auditable.
//!
//! # Safety invariants
//!
//! - Every wrapper field is a non-null pointer to a live AWS-LC object of
//!   the named type for the lifetime of the wrapper.
//! - `from_raw` callers must transfer ownership of a freshly-allocated
//!   object; double-free is undefined behaviour.
//! - The wrappers are `Send` because AWS-LC handles are safe to move between
//!   threads (`SSL_CTX_up_ref` is the cross-thread sharing primitive, not
//!   raw cloning). They are deliberately *not* `Sync`: `SSL` in particular
//!   is single-threaded; concurrent calls on one handle are UB.

// `EvpPkey` and `X509` are not consumed yet (PEM-bytes loader uses the
// PEM_read_bio_* path directly without intermediate Rust ownership for now);
// they stay in the public-internal API as the foundation for future
// per-cert/key surfaces.
#![allow(dead_code)]

use std::ptr::NonNull;

/// Owned `SSL_CTX *`. Freed with `SSL_CTX_free` on drop.
#[derive(Debug)]
pub struct SslCtx(NonNull<aws_lc_sys::SSL_CTX>);

impl SslCtx {
    /// Take ownership of a freshly-allocated `SSL_CTX *`. Returns `None`
    /// if the input is null.
    ///
    /// # Safety
    ///
    /// `ptr` must come from `SSL_CTX_new` (or a function documented to
    /// transfer ownership of an `SSL_CTX` reference) and must not be freed
    /// by the caller — this wrapper takes that responsibility on drop.
    /// Use [`Clone`] to obtain additional owners; do not wrap the same
    /// pointer twice via `from_raw`.
    pub unsafe fn from_raw(ptr: *mut aws_lc_sys::SSL_CTX) -> Option<Self> {
        NonNull::new(ptr).map(Self)
    }

    /// Borrow the underlying pointer for an FFI call. The returned pointer
    /// is valid for the lifetime of `&self`.
    #[must_use]
    pub fn as_ptr(&self) -> *mut aws_lc_sys::SSL_CTX {
        self.0.as_ptr()
    }
}

impl Clone for SslCtx {
    fn clone(&self) -> Self {
        // SAFETY: `self.0` is a live SSL_CTX for the lifetime of `self`;
        // `SSL_CTX_up_ref` atomically bumps its reference count. The
        // returned wrapper owns one of those references and will drop it
        // via `SSL_CTX_free`, which decrements and only frees at zero.
        let ok = unsafe { aws_lc_sys::SSL_CTX_up_ref(self.0.as_ptr()) };
        assert_eq!(ok, 1, "SSL_CTX_up_ref failed");
        Self(self.0)
    }
}

impl Drop for SslCtx {
    fn drop(&mut self) {
        // SAFETY: `self.0` was a live SSL_CTX produced by AWS-LC for the
        // lifetime of `self`. `SSL_CTX_free` decrements the refcount and
        // only frees the object when it reaches zero, so cloning via
        // `SSL_CTX_up_ref` remains sound.
        unsafe {
            aws_lc_sys::SSL_CTX_free(self.0.as_ptr());
        }
    }
}

// SAFETY: AWS-LC's SSL_CTX is documented to be safe to share read-only
// across threads via `SSL_CTX_up_ref`. Moving the owning handle between
// threads is therefore safe; we deliberately do not implement `Sync` because
// the FFI surface contains mutating operations (e.g. `SSL_CTX_set_*`) that
// are not internally synchronised.
unsafe impl Send for SslCtx {}

/// Owned `SSL *`. Freed with `SSL_free` on drop.
#[derive(Debug)]
pub struct Ssl(NonNull<aws_lc_sys::SSL>);

impl Ssl {
    /// # Safety
    ///
    /// `ptr` must come from `SSL_new` (or a function documented to transfer
    /// ownership of an `SSL`) and must not be freed by the caller.
    pub unsafe fn from_raw(ptr: *mut aws_lc_sys::SSL) -> Option<Self> {
        NonNull::new(ptr).map(Self)
    }

    #[must_use]
    pub fn as_ptr(&self) -> *mut aws_lc_sys::SSL {
        self.0.as_ptr()
    }
}

impl Drop for Ssl {
    fn drop(&mut self) {
        // SAFETY: `self.0` was a live SSL for the lifetime of `self`,
        // owned uniquely, never freed by anyone else.
        unsafe {
            aws_lc_sys::SSL_free(self.0.as_ptr());
        }
    }
}

// SAFETY: An individual SSL handle is single-threaded but may be moved
// between threads as long as concurrent access is externally serialised.
// Not `Sync`: simultaneous SSL_read/SSL_write on one handle is UB.
unsafe impl Send for Ssl {}

/// Owned `BIO *`. Freed with `BIO_free` on drop.
#[derive(Debug)]
pub struct Bio(NonNull<aws_lc_sys::BIO>);

impl Bio {
    /// # Safety
    ///
    /// `ptr` must come from `BIO_new` (or any AWS-LC function documented to
    /// return an owned `BIO *`) and must not be freed by the caller, nor
    /// installed into an `SSL` that would also free it (`SSL_set_bio`
    /// transfers ownership; do not wrap such a pointer).
    pub unsafe fn from_raw(ptr: *mut aws_lc_sys::BIO) -> Option<Self> {
        NonNull::new(ptr).map(Self)
    }

    #[must_use]
    pub fn as_ptr(&self) -> *mut aws_lc_sys::BIO {
        self.0.as_ptr()
    }

    /// Consume the wrapper and return the raw pointer without freeing it.
    /// Use when handing ownership off to an AWS-LC function that takes it
    /// (`SSL_set_bio`, `BIO_push`, etc.).
    #[must_use]
    pub fn into_raw(self) -> *mut aws_lc_sys::BIO {
        let ptr = self.0.as_ptr();
        std::mem::forget(self);
        ptr
    }
}

impl Drop for Bio {
    fn drop(&mut self) {
        // SAFETY: `self.0` was a live BIO for the lifetime of `self`,
        // ownership not transferred elsewhere.
        unsafe {
            aws_lc_sys::BIO_free(self.0.as_ptr());
        }
    }
}

// SAFETY: BIOs may be moved between threads; concurrent access is not safe
// (no `Sync`).
unsafe impl Send for Bio {}

/// Owned `EVP_PKEY *`. Freed with `EVP_PKEY_free` on drop.
#[derive(Debug)]
pub struct EvpPkey(NonNull<aws_lc_sys::EVP_PKEY>);

impl EvpPkey {
    /// # Safety
    ///
    /// `ptr` must come from one of AWS-LC's `EVP_PKEY` constructors
    /// (`EVP_PKEY_new`, `PEM_read_bio_PrivateKey`, …) and must not be
    /// freed elsewhere.
    pub unsafe fn from_raw(ptr: *mut aws_lc_sys::EVP_PKEY) -> Option<Self> {
        NonNull::new(ptr).map(Self)
    }

    #[must_use]
    pub fn as_ptr(&self) -> *mut aws_lc_sys::EVP_PKEY {
        self.0.as_ptr()
    }
}

impl Drop for EvpPkey {
    fn drop(&mut self) {
        // SAFETY: `self.0` was a live EVP_PKEY for the lifetime of `self`,
        // owned uniquely.
        unsafe {
            aws_lc_sys::EVP_PKEY_free(self.0.as_ptr());
        }
    }
}

// SAFETY: EVP_PKEY is safe to move between threads.
unsafe impl Send for EvpPkey {}

/// Owned `X509 *`. Freed with `X509_free` on drop.
#[derive(Debug)]
pub struct X509(NonNull<aws_lc_sys::X509>);

impl X509 {
    /// # Safety
    ///
    /// `ptr` must come from an AWS-LC function that transfers ownership
    /// of an `X509 *` (`X509_new`, `PEM_read_bio_X509`, …).
    pub unsafe fn from_raw(ptr: *mut aws_lc_sys::X509) -> Option<Self> {
        NonNull::new(ptr).map(Self)
    }

    #[must_use]
    pub fn as_ptr(&self) -> *mut aws_lc_sys::X509 {
        self.0.as_ptr()
    }
}

impl Drop for X509 {
    fn drop(&mut self) {
        // SAFETY: `self.0` was a live X509 for the lifetime of `self`,
        // owned uniquely.
        unsafe {
            aws_lc_sys::X509_free(self.0.as_ptr());
        }
    }
}

// SAFETY: X509 is safe to move between threads (reads only; mutation is
// not part of our surface).
unsafe impl Send for X509 {}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_server_ctx() -> SslCtx {
        // SAFETY: TLS_server_method returns a static SSL_METHOD pointer;
        // SSL_CTX_new returns either an owned pointer or null on alloc
        // failure.
        let raw = unsafe { aws_lc_sys::SSL_CTX_new(aws_lc_sys::TLS_server_method()) };
        // SAFETY: `raw` is the fresh SSL_CTX we just owned (or null).
        unsafe { SslCtx::from_raw(raw) }.expect("SSL_CTX_new (server) returned null")
    }

    fn new_client_ctx() -> SslCtx {
        // SAFETY: TLS_client_method returns a static SSL_METHOD pointer.
        let raw = unsafe { aws_lc_sys::SSL_CTX_new(aws_lc_sys::TLS_client_method()) };
        // SAFETY: see above.
        unsafe { SslCtx::from_raw(raw) }.expect("SSL_CTX_new (client) returned null")
    }

    #[test]
    fn server_ctx_constructs_and_drops() {
        let ctx = new_server_ctx();
        assert!(!ctx.as_ptr().is_null());
        // Drop runs at end of scope.
    }

    #[test]
    fn client_ctx_constructs_and_drops() {
        let ctx = new_client_ctx();
        assert!(!ctx.as_ptr().is_null());
    }

    #[test]
    fn ssl_handle_round_trips_through_ctx() {
        let ctx = new_server_ctx();
        // SAFETY: ctx.as_ptr() is a live SSL_CTX; SSL_new returns either an
        // owned SSL or null on alloc failure.
        let raw = unsafe { aws_lc_sys::SSL_new(ctx.as_ptr()) };
        // SAFETY: `raw` is the freshly-allocated SSL we just owned.
        let ssl = unsafe { Ssl::from_raw(raw) }.expect("SSL_new returned null");
        assert!(!ssl.as_ptr().is_null());
    }

    #[test]
    fn from_raw_null_returns_none() {
        // SAFETY: passing null is explicitly handled; no ownership is
        // claimed and the wrapper short-circuits to None.
        assert!(unsafe { SslCtx::from_raw(std::ptr::null_mut()) }.is_none());
        // SAFETY: same.
        assert!(unsafe { Ssl::from_raw(std::ptr::null_mut()) }.is_none());
        // SAFETY: same.
        assert!(unsafe { Bio::from_raw(std::ptr::null_mut()) }.is_none());
    }

    #[test]
    fn bio_mem_constructs_and_drops() {
        // SAFETY: BIO_s_mem returns a static BIO_METHOD; BIO_new returns
        // either an owned BIO or null on alloc failure.
        let raw = unsafe { aws_lc_sys::BIO_new(aws_lc_sys::BIO_s_mem()) };
        // SAFETY: `raw` is the freshly-allocated BIO we just owned.
        let bio = unsafe { Bio::from_raw(raw) }.expect("BIO_new returned null");
        assert!(!bio.as_ptr().is_null());
    }

    #[test]
    fn bio_into_raw_releases_ownership() {
        // SAFETY: BIO_new returns an owned BIO or null.
        let raw = unsafe { aws_lc_sys::BIO_new(aws_lc_sys::BIO_s_mem()) };
        // SAFETY: `raw` is the freshly-allocated BIO we just owned.
        let bio = unsafe { Bio::from_raw(raw) }.expect("BIO_new returned null");
        let leaked = bio.into_raw();
        assert_eq!(leaked, raw);
        // Re-take ownership so we don't actually leak in the test.
        // SAFETY: we are the unique owner of `leaked` after `into_raw`.
        let _retaken = unsafe { Bio::from_raw(leaked) }.expect("non-null");
    }

    #[test]
    fn many_contexts_do_not_leak_under_repeated_construction() {
        // A weak smoke test for the Drop impl: if SSL_CTX_free isn't being
        // called we'd see process RSS grow without bound. The number is
        // large enough to be obvious in `leaks` / valgrind but cheap enough
        // for `cargo test`.
        for _ in 0..1024 {
            let _ = new_server_ctx();
        }
    }

    #[test]
    fn ssl_ctx_clone_shares_underlying_handle() {
        let ctx = new_server_ctx();
        let raw = ctx.as_ptr();
        let cloned = ctx.clone();
        assert_eq!(cloned.as_ptr(), raw, "Clone must alias the same SSL_CTX");
        // Drop the original; the clone still holds a refcount, so the
        // pointer must remain usable. We exercise it through an SSL_new
        // round-trip — if the refcount was wrong we'd be reading freed
        // memory and either segfault or trip the allocator.
        drop(ctx);
        // SAFETY: `cloned` still owns a live refcount on the SSL_CTX.
        let ssl_raw = unsafe { aws_lc_sys::SSL_new(cloned.as_ptr()) };
        // SAFETY: `ssl_raw` is freshly owned.
        let _ssl = unsafe { Ssl::from_raw(ssl_raw) }.expect("SSL_new after clone+drop");
    }

    #[test]
    fn ssl_ctx_clone_then_drop_all_does_not_leak() {
        // Same intent as `many_contexts_do_not_leak_under_repeated_construction`,
        // but exercising the refcount path. 512 ctx × 2 clones each = 1536
        // SSL_CTX_free calls expected, and each underlying object freed
        // exactly once.
        for _ in 0..512 {
            let ctx = new_server_ctx();
            let a = ctx.clone();
            let b = ctx.clone();
            drop(ctx);
            drop(a);
            drop(b);
        }
    }
}
