use security_framework::trust_settings::{
    Domain,
    TrustSettings,
    TrustSettingsForCertificate
};
use rustls::RootCertStore;
use std::io::{Error, ErrorKind};
use std::collections::HashMap;

pub fn load_native_certs() -> Result<RootCertStore, Error> {
    let mut store = RootCertStore::empty();

    // The various domains are designed to interact like this:
    //
    // "Per-user Trust Settings override locally administered
    //  Trust Settings, which in turn override the System Trust
    //  Settings."
    //
    // So we collect the certificates in this order; as a map of
    // their DER encoding to what we'll do with them.  We don't
    // overwrite existing elements, which mean User settings
    // trump Admin trump System, as desired.

    let mut all_certs = HashMap::new();

    for domain in &[Domain::User, Domain::Admin, Domain::System] {
        let ts = TrustSettings::new(*domain);
        let iter = ts.iter()
            .map_err(|err| Error::new(ErrorKind::Other, err))?;

        for cert in iter {
            let der = cert.to_der();
            let trusted = ts.tls_trust_settings_for_certificate(&cert)
                .map_err(|err| Error::new(ErrorKind::Other, err))?;

            all_certs.entry(der)
                .or_insert(trusted);
        }
    }

    // Now we have all the certificates and an idea of whether
    // to use them.
    for (der, trusted) in all_certs.drain() {
        match trusted {
            TrustSettingsForCertificate::TrustRoot |
                TrustSettingsForCertificate::TrustAsRoot => {
                store.add(&rustls::Certificate(der))
                    .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
            },
            _ => {} // discard
        }
    }

    Ok(store)
}
