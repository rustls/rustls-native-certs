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
use std::io::{Error, ErrorKind};
use std::io::BufRead;

pub trait RootStoreBuilder {
    fn load_der(&mut self, der: Vec<u8>) -> Result<(), Error>;
    fn load_pem_file(&mut self, rd: &mut dyn BufRead) -> Result<(), Error>;
}

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
    struct RootCertStoreLoader {
        store: RootCertStore,
    };
    impl RootStoreBuilder for RootCertStoreLoader {
        fn load_der(&mut self, der: Vec<u8>) -> Result<(), Error> {
            self.store.add(&rustls::Certificate(der))
                .map_err(|err| Error::new(ErrorKind::InvalidData, err))
        }
        fn load_pem_file(&mut self, rd: &mut dyn BufRead) -> Result<(), Error> {
            self.store.add_pem_file(rd)
                .map(|_| ())
                .map_err(|()| Error::new(ErrorKind::InvalidData, format!("could not load PEM file")))
        }
    }
    let mut loader = RootCertStoreLoader {
        store: RootCertStore::empty(),
    };
    match build_native_certs(&mut loader) {
        Err(err) if loader.store.is_empty() => Err((None, err)),
        Err(err) => Err((Some(loader.store), err)),
        Ok(()) => Ok(loader.store),
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
