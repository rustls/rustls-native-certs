use schannel;
use rustls::RootCertStore;
use std::io::{Error, ErrorKind};

pub fn load_native_certs() -> Result<RootCertStore, Error> {
    let mut store = RootCertStore::empty();

    let local_machine_store = schannel::cert_store::CertStore::open_local_machine("ROOT")?;
    let current_user_store = schannel::cert_store::CertStore::open_current_user("ROOT")?;

    for cert in local_machine_store.certs() {
        store.add(&rustls::Certificate(cert.to_der().to_vec()))
            .map_err(|err| Error::new(ErrorKind::InvalidData, err))?
    }

    for cert in current_user_store.certs() {
        store.add(&rustls::Certificate(cert.to_der().to_vec()))
            .map_err(|err| Error::new(ErrorKind::InvalidData, err))?
    }

    Ok(store)
}
