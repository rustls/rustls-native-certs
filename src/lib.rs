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

#[cfg(feature = "rustls")]
mod rustls;

#[cfg(feature = "webpki")]
mod webpki;

use std::io::BufRead;
use std::io::Error;

/// Like `Result<T,E>`, but allows for functions that can return partially complete
/// work alongside an error.
pub type PartialResult<T, E> = Result<T, (Option<T>, E)>;

#[cfg(feature = "rustls")]
pub use crate::rustls::load_to_rustls;

#[cfg(feature = "webpki")]
pub use crate::webpki::load_to_webpki;

// log for logging (optional).
#[cfg(feature = "logging")]
use log::debug;

#[cfg(not(feature = "logging"))]
#[macro_use]
mod log {
    macro_rules! debug    ( ($($tt:tt)*) => {{}} );
}

pub trait RootStoreBuilder {
    fn load_der(&mut self, der: Vec<u8>) -> Result<(), Error>;

    // A default implementation that ignores invalid certs
    // and sections that aren't for public certificates.
    // Code from rustls::RootCertStore::add_parseable_certificates.
    #[cfg_attr(not(feature = "logging"), allow(unused_variables))]
    fn load_pem_file(&mut self, rd: &mut dyn BufRead) -> Result<(), Error> {
        let mut valid_count = 0;
        let mut invalid_count = 0;

        for der_cert in rustls_pemfile::certs(rd)? {
            match self.load_der(der_cert) {
                Ok(_) => valid_count += 1,
                Err(err) => {
                    debug!("certificate parsing failed: {:?}", err);
                    invalid_count += 1
                }
            }
        }

        debug!(
            "load_pem_file processed {} valid and {} invalid certs",
            valid_count, invalid_count
        );

        Ok(())
    }
}

/// Loads root certificates found in the platform's native certificate
/// store, executing callbacks on the provided builder.
///
/// This function fails in a platform-specific way, expressed in a `std::io::Error`.
///
/// This function can be expensive: on some platforms it involves loading
/// and parsing a ~300KB disk file.  It's therefore prudent to call
/// this sparingly.
pub fn build_native_certs<B: RootStoreBuilder>(builder: &mut B) -> Result<(), Error> {
    platform::build_native_certs(builder)
}
