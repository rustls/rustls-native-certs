use std::io::Error;

use pki_types::CertificateDer;
use schannel::cert_context::ValidUses;
use schannel::cert_store::CertStore;

pub fn load_native_certs() -> Result<Vec<CertificateDer<'static>>, Error> {
    let mut certs = Vec::new();

    let current_user_store = CertStore::open_current_user("ROOT")?;

    for cert in current_user_store.certs() {
        if usable_for_rustls(cert.valid_uses().unwrap()) && cert.is_time_valid().unwrap() {
            certs.push(CertificateDer::from(cert.to_der().to_vec()));
        }
    }

    Ok(certs)
}

fn usable_for_rustls(uses: ValidUses) -> bool {
    match uses {
        ValidUses::All => true,
        ValidUses::Oids(strs) => strs
            .iter()
            .any(|x| x == PKIX_SERVER_AUTH),
    }
}

static PKIX_SERVER_AUTH: &str = "1.3.6.1.5.5.7.3.1";
