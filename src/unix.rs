use crate::Certificate;

use std::io::{Error, ErrorKind};
use std::io::BufReader;
use std::fs::File;
use std::path::Path;

fn load_file(certs: &mut Vec<Certificate>, path: &Path) -> Result<(), Error> {
    let f = File::open(&path)?;
    let mut f = BufReader::new(f);
    match rustls_pemfile::certs(&mut f) {
        Ok(contents) => {
            certs.extend(contents.into_iter().map(Certificate));
            Ok(())
        }
        Err(_) => Err(Error::new(
            ErrorKind::InvalidData,
            format!("Could not load PEM file {:?}", path),
        )),
    }
}

pub fn load_native_certs() -> Result<Vec<Certificate>, Error> {
    let likely_locations = openssl_probe::probe();
    let mut first_error = None;
    let mut certs = Vec::new();

    if let Some(file) = likely_locations.cert_file {
        if let Err(err) = load_file(&mut certs, &file) {
            first_error = first_error.or(Some(err));
        }
    }

    if let Some(err) = first_error {
        Err(err)
    } else {
        Ok(certs)
    }
}
