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

use std::io::{Error, ErrorKind};
use std::io::BufReader;
use std::fs::File;
use std::path::{Path,PathBuf};
use std::env;

/// Loads root certificates found in the platform's native certificate
/// store, executing callbacks on the provided builder.
///
/// This function fails in a platform-specific way, expressed in a `std::io::Error`.
///
/// This function can be expensive: on some platforms it involves loading
/// and parsing a ~300KB disk file.  It's therefore prudent to call
/// this sparingly.
pub fn load_native_certs() -> Result<Vec<Certificate>, Error> {
    load_certs_from_env()
    .unwrap_or_else(platform::load_native_certs)
}

pub struct Certificate(pub Vec<u8>);

const ENV_CERT_FILE: &str = "SSL_CERT_FILE";

/// Returns None if SSL_CERT_FILE is not defined in the current environment.
///
/// If it is defined, it is always used, so it must be a path to a real
/// file from which certificates can be loaded successfully.
fn load_certs_from_env() -> Option<Result<Vec<Certificate>, Error>> {
    let cert_var_path = PathBuf::from(
        env::var_os(ENV_CERT_FILE)?
    );

    Some(load_pem_certs(&cert_var_path))
}

fn load_pem_certs(path: &Path) -> Result<Vec<Certificate>, Error> {
    let f = File::open(&path)?;
    let mut f = BufReader::new(f);

    match rustls_pemfile::certs(&mut f) {
        Ok(contents) => {
            Ok(contents.into_iter().map(Certificate).collect())
        }
        Err(_) => Err(Error::new(
            ErrorKind::InvalidData,
            format!("Could not load PEM file {:?}", path),
        )),
    }
}