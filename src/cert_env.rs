use crate::Certificate;
use crate::cert_file;

use std::env;
use std::io::Error;
use std::path::PathBuf;

const ENV_CERT_FILE: &'static str = "SSL_CERT_FILE";

/// Returns None if SSL_CERT_FILE is not defined in the current environment.
///
/// If it is defined, it is always used, so it must be a path to a real
/// file from which certificates can be loaded successfully.
pub fn load_certs_from_env() -> Option<Result<Vec<Certificate>, Error>> {
    let cert_var_path = PathBuf::from(
        env::var_os(ENV_CERT_FILE)?
    );

    Some(cert_file::load_pem_certs(&cert_var_path))
}