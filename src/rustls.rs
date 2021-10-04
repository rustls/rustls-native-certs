use crate::RootStoreBuilder;

use rustls::RootCertStore;

use std::io::{Error, ErrorKind};

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
///
/// *This function is available only if the crate is built with the "rustls" feature.*
pub fn load_to_rustls() -> crate::PartialResult<RootCertStore, Error> {
    struct RootCertStoreLoader {
        store: RootCertStore,
    }
    impl RootStoreBuilder for RootCertStoreLoader {
        fn load_der(&mut self, der: Vec<u8>) -> Result<(), Error> {
            self.store
                .add(&rustls::Certificate(der))
                .map_err(|err| Error::new(ErrorKind::InvalidData, err))
        }
    }
    let mut loader = RootCertStoreLoader {
        store: RootCertStore::empty(),
    };
    match crate::build_native_certs(&mut loader) {
        Err(err) if loader.store.is_empty() => Err((None, err)),
        Err(err) => Err((Some(loader.store), err)),
        Ok(()) => Ok(loader.store),
    }
}
