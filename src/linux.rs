use openssl_probe;
use rustls::RootCertStore;
use std::io::{Error, ErrorKind};
use std::io::BufReader;
use std::fs::File;
use std::path::Path;

fn load_file(store: &mut RootCertStore, path: &Path) -> Result<(), Error> {
    let f = File::open(&path)?;
    let mut f = BufReader::new(f);
    if store.add_pem_file(&mut f).is_err() {
        Err(Error::new(ErrorKind::InvalidData,
                       format!("Could not load PEM file {:?}", path)))
    } else {
        Ok(())
    }
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
pub fn load_native_certs() -> Result<RootCertStore, Error> {
    let likely_locations = openssl_probe::probe();
    let mut store = RootCertStore::empty();

    if let Some(file) = likely_locations.cert_file {
        load_file(&mut store, &file)?;
    }

    Ok(store)
}
