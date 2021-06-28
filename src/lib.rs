//! rustls-native-certs allows rustls to use the platform's native certificate
//! store when operating as a TLS client.
//!
//! It provides the following functions:
//! * A higher level function [load_native_certs](fn.build_native_certs.html)
//!   which returns a `rustls::RootCertStore` pre-filled from the native
//!   certificate store. It is only available if the `rustls` feature is
//!   enabled.
//! * A lower level function [build_native_certs](fn.build_native_certs.html)
//!   that lets callers pass their own certificate parsing logic. It is
//!   available to all users.

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

use std::io::Error;

/// Loads root certificates found in the platform's native certificate
/// store, executing callbacks on the provided builder.
///
/// This function fails in a platform-specific way, expressed in a `std::io::Error`.
///
/// This function can be expensive: on some platforms it involves loading
/// and parsing a ~300KB disk file.  It's therefore prudent to call
/// this sparingly.
pub fn load_native_certs() -> Result<Vec<Certificate>, Error> {
    platform::load_native_certs()
}

pub struct Certificate(pub Vec<u8>);
