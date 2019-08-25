use security_framework::item;
use security_framework::os::macos::item::ItemSearchOptionsExt;
use security_framework::os::macos::keychain;
use rustls::RootCertStore;
use std::io::{Error, ErrorKind};

pub fn load_native_certs() -> Result<RootCertStore, Error> {
    let mut store = RootCertStore::empty();

    let keychain = keychain::SecKeychain::open("/Library/Keychains/System.keychain")
        .map_err(|err| Error::new(ErrorKind::PermissionDenied, err))?;

    let results = item::ItemSearchOptions::new()
        .class(item::ItemClass::certificate())
        .load_refs(true)
        .keychains(&[keychain])
        .search()
        .map_err(|err| Error::new(ErrorKind::Other, err))?;

    for result in &results {
        if let item::SearchResult::Ref(cert_ref) = result {
            if let item::Reference::Certificate(cert) = cert_ref {
                println!("cert: {:?}", cert.subject_summary());
                store.add(&rustls::Certificate(cert.to_der()))
                    .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
            }
        }
    }

    Ok(store)
}
