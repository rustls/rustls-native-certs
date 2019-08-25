use security_framework::item;
use rustls::RootCertStore;
use std::io::{Error, ErrorKind};

pub fn load_native_certs() -> Result<RootCertStore, Error> {
    let mut store = RootCertStore::empty();

    let results = item::ItemSearchOptions::new()
        .class(item::ItemClass::certificate())
        .load_refs(true)
        .search();

    for result in results {
        if let item::SearchResult::Ref(cert_ref) = result {
            if let item::Reference::Certificate(cert) = cert_ref {
                store.add(&rustls::Certificate(cert.to_der()))
                    .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
            }
        }
    }

    Ok(store)
}
