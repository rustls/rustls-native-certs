//! rustls-native-certs allows rustls to use the platform's native certificate
//! store when operating as a TLS client.
//!
//! It provides a single function [`load_native_certs()`], which returns a
//! collection of certificates found by reading the platform-native
//! certificate store.
//!
//! If the SSL_CERT_FILE environment variable is set, certificates (in PEM
//! format) are read from that file instead.
//!
//! If you want to load these certificates into a `rustls::RootCertStore`,
//! you'll likely want to do something like this:
//!
//! ```no_run
//! let mut roots = rustls::RootCertStore::empty();
//! for cert in rustls_native_certs::load_native_certs().expect("could not load platform certs") {
//!     roots.add(cert).unwrap();
//! }
//! ```

// Enable documentation for all features on docs.rs
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

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

use std::env;
use std::fs::File;
use std::io::BufReader;
use std::io::{Error, ErrorKind};
use std::path::{Path, PathBuf};

use pki_types::CertificateDer;

/// Load root certificates found in the platform's native certificate store.
///
/// If the SSL_CERT_FILE environment variable is set, certificates (in PEM
/// format) are read from that file instead.
///
/// ## Certificate Validity
///
/// All certificates are expected to be in PEM format. A file may contain
/// multiple certificates.
///
/// Example:
///
/// ```text
/// -----BEGIN CERTIFICATE-----
/// MIICGzCCAaGgAwIBAgIQQdKd0XLq7qeAwSxs6S+HUjAKBggqhkjOPQQDAzBPMQsw
/// CQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2gg
/// R3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMjAeFw0yMDA5MDQwMDAwMDBaFw00
/// MDA5MTcxNjAwMDBaME8xCzAJBgNVBAYTAlVTMSkwJwYDVQQKEyBJbnRlcm5ldCBT
/// ZWN1cml0eSBSZXNlYXJjaCBHcm91cDEVMBMGA1UEAxMMSVNSRyBSb290IFgyMHYw
/// EAYHKoZIzj0CAQYFK4EEACIDYgAEzZvVn4CDCuwJSvMWSj5cz3es3mcFDR0HttwW
/// +1qLFNvicWDEukWVEYmO6gbf9yoWHKS5xcUy4APgHoIYOIvXRdgKam7mAHf7AlF9
/// ItgKbppbd9/w+kHsOdx1ymgHDB/qo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0T
/// AQH/BAUwAwEB/zAdBgNVHQ4EFgQUfEKWrt5LSDv6kviejM9ti6lyN5UwCgYIKoZI
/// zj0EAwMDaAAwZQIwe3lORlCEwkSHRhtFcP9Ymd70/aTSVaYgLXTWNLxBo1BfASdW
/// tL4ndQavEi51mI38AjEAi/V3bNTIZargCyzuFJ0nN6T5U6VR5CmD1/iQMVtCnwr1
/// /q4AaOeMSQ+2b1tbFfLn
/// -----END CERTIFICATE-----
/// -----BEGIN CERTIFICATE-----
/// MIIBtjCCAVugAwIBAgITBmyf1XSXNmY/Owua2eiedgPySjAKBggqhkjOPQQDAjA5
/// MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6b24g
/// Um9vdCBDQSAzMB4XDTE1MDUyNjAwMDAwMFoXDTQwMDUyNjAwMDAwMFowOTELMAkG
/// A1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJvb3Qg
/// Q0EgMzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCmXp8ZBf8ANm+gBG1bG8lKl
/// ui2yEujSLtf6ycXYqm0fc4E7O5hrOXwzpcVOho6AF2hiRVd9RFgdszflZwjrZt6j
/// QjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBSr
/// ttvXBp43rDCGB5Fwx5zEGbF4wDAKBggqhkjOPQQDAgNJADBGAiEA4IWSoxe3jfkr
/// BqWTrBqYaGFy+uGh0PsceGCmQ5nFuMQCIQCcAu/xlJyzlvnrxir4tiz+OpAUFteM
/// YyRIHN8wfdVoOw==
/// -----END CERTIFICATE-----
///
/// ```
///
/// For reasons of compatibility, an attempt is made to skip invalid sections
/// of a certificate file but this means it's also possible for a malformed
/// certificate to be skipped.
///
/// If a certificate isn't loaded, and no error is reported, check if:
///
/// 1. the certificate is in PEM format (see example above)
/// 2. *BEGIN CERTIFICATE* line starts with exactly five hyphens (`'-'`)
/// 3. *END CERTIFICATE* line ends with exactly five hyphens (`'-'`)
/// 4. there is a line break after the certificate.
///
/// ## Errors
///
/// This function fails in a platform-specific way, expressed in a `std::io::Error`.
///
/// ## Caveats
///
/// This function can be expensive: on some platforms it involves loading
/// and parsing a ~300KB disk file.  It's therefore prudent to call
/// this sparingly.
pub fn load_native_certs() -> Result<Vec<CertificateDer<'static>>, Error> {
    load_certs_from_env().unwrap_or_else(platform::load_native_certs)
}

const ENV_CERT_FILE: &str = "SSL_CERT_FILE";

/// Returns None if SSL_CERT_FILE is not defined in the current environment.
///
/// If it is defined, it is always used, so it must be a path to an existing,
/// accessible file from which certificates can be loaded successfully. While parsing,
/// [rustls_pemfile::certs()] parser will ignore parts of the file which are
/// not considered part of a certificate. Certificates which are not in the right
/// format (PEM) or are otherwise corrupted may get ignored silently.
fn load_certs_from_env() -> Option<Result<Vec<CertificateDer<'static>>, Error>> {
    let cert_var_path = PathBuf::from(env::var_os(ENV_CERT_FILE)?);

    Some(load_pem_certs(&cert_var_path))
}

fn load_pem_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, Error> {
    let mut f = BufReader::new(File::open(path)?);
    rustls_pemfile::certs(&mut f)
        .map(|result| match result {
            Ok(der) => Ok(der),
            Err(err) => Err(Error::new(
                ErrorKind::InvalidData,
                format!("could not load PEM file {path:?}: {err}"),
            )),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_file_from_env() {
        // Certificate parser tries to extract certs from file ignoring
        // invalid sections.
        let certs = load_pem_certs(Path::new(file!())).unwrap();
        assert_eq!(certs.len(), 0);
    }

    #[test]
    fn from_env_missing_file() {
        assert_eq!(
            load_pem_certs(Path::new("no/such/file"))
                .unwrap_err()
                .kind(),
            ErrorKind::NotFound
        );
    }

    #[test]
    #[cfg(unix)]
    fn from_env_with_non_regular_and_empty_file() {
        let certs = load_pem_certs(Path::new("/dev/null")).unwrap();
        assert_eq!(certs.len(), 0);
    }
}
