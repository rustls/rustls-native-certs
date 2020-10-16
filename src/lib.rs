//! rustls-native-certs allows rustls to use the platform's native certificate
//! store when operating as a TLS client.
//!
//! It consists of a single function [load_native_certs](fn.load_native_certs.html) which returns a
//! `rustls::RootCertStore` pre-filled from the native certificate store.

/// Like `Result<T,E>`, but allows for functions that can return partially complete
/// work alongside an error.
pub type PartialResult<T, E> = Result<T, (Option<T>, E)>;

#[cfg(all(unix, not(target_os = "macos")))]
mod unix;
#[cfg(all(unix, not(target_os = "macos")))]
use unix as platform;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as platform;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as platform;

use rustls::RootCertStore;
use std::io::Error;

/// Loads root certificates found in the platform's native certificate
/// store.
///
/// On success, this returns a `rustls::RootCertStore` loaded with a
/// snapshop of the root certificates found on this platform.  This
/// function fails in a platform-specific way, expressed in a `std::io::Error`.
///
/// This function can be expensive: on some platforms it involves loading
/// and parsing a ~300KB disk file.  It's therefore prudent to call
/// this sparingly.
pub fn load_native_certs() -> PartialResult<RootCertStore, Error> {
    platform::load_native_certs()
}
