use schannel;
use rustls::RootCertStore;
use std::io::{Error, ErrorKind};

static PKIX_SERVER_AUTH: &str = "1.3.6.1.5.5.7.3.1";

fn usable_for_rustls(uses: schannel::cert_context::ValidUses) -> bool {
    match uses {
        schannel::cert_context::ValidUses::All => true,
        schannel::cert_context::ValidUses::Oids(strs) => {
            strs.iter().any(|x| x == PKIX_SERVER_AUTH)
        }
    }
}

/// Loads root certificates found in the platform's native certificate
/// store.
///
/// On success, this returns a `rustls::RootCertStore` loaded with a
/// snapshop of the root certificates found on this platform.  This
/// function fails in a platform-specific way, expressed in a `std::io::Error`.
///
/// This function can be expensive: on some platforms it involves loading
/// and parsing a ~300KB disk file.  It's therefore prudent to call
/// this sparingly.
pub fn load_native_certs() -> Result<RootCertStore, Error> {
    let mut store = RootCertStore::empty();

    let current_user_store = schannel::cert_store::CertStore::open_current_user("ROOT")?;

    for cert in current_user_store.certs() {
        if !usable_for_rustls(cert.valid_uses().unwrap()) {
            continue;
        }

        store.add(&rustls::Certificate(cert.to_der().to_vec()))
            .map_err(|err| Error::new(ErrorKind::InvalidData, err))?
    }

    Ok(store)
}
