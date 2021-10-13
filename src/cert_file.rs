use crate::Certificate;

use std::io::{Error, ErrorKind};
use std::io::BufReader;
use std::fs::File;
use std::path::Path;

pub fn load_pem_certs(path: &Path) -> Result<Vec<Certificate>, Error> {
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