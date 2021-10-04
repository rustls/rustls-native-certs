use webpki::TrustAnchor;

use crate::RootStoreBuilder;

// Similar to the rustls type with that name, except type privacy
// doesn't prevent us from accessing to the data
#[derive(Debug)]
pub struct OwnedTrustAnchor {
    subject: Vec<u8>,
    spki: Vec<u8>,
    name_constraints: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct OwnedTrustAnchors {
    anchors: Vec<OwnedTrustAnchor>,
}

impl OwnedTrustAnchor {
    fn try_from_cert_der(der: &[u8]) -> Result<Self, webpki::Error> {
        let anchor = TrustAnchor::try_from_cert_der(der)?;
        Ok(Self {
            subject: anchor.subject.to_owned(),
            spki: anchor.spki.to_owned(),
            name_constraints: anchor.name_constraints.map(ToOwned::to_owned),
        })
    }

    // Impl note: neither Borrow nor AsRef traits work here, due to the
    // lifetime in webpki::TrustAnchor
    fn as_ref(&self) -> webpki::TrustAnchor<'_> {
        webpki::TrustAnchor {
            subject: &self.subject,
            spki: &self.spki,
            name_constraints: self.name_constraints.as_deref(),
        }
    }
}

impl IntoIterator for OwnedTrustAnchors {
    type Item = OwnedTrustAnchor;

    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.anchors.into_iter()
    }
}

impl OwnedTrustAnchors {
    pub fn iter(&self) -> impl Iterator<Item = TrustAnchor<'_>> {
        self.anchors.iter().map(|ota| ota.as_ref())
    }

    pub fn len(&self) -> usize {
        self.anchors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }
}

pub fn load_to_webpki() -> crate::PartialResult<OwnedTrustAnchors, std::io::Error> {
    struct RootCertStoreLoader {
        store: OwnedTrustAnchors,
    }

    impl RootStoreBuilder for RootCertStoreLoader {
        fn load_der(&mut self, der: Vec<u8>) -> Result<(), std::io::Error> {
            self.store.anchors.push(
                OwnedTrustAnchor::try_from_cert_der(der.as_slice())
                    .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?,
            );
            Ok(())
        }
    }

    let mut loader = RootCertStoreLoader {
        store: OwnedTrustAnchors {
            anchors: Vec::new(),
        },
    };

    match crate::build_native_certs(&mut loader) {
        Err(err) if loader.store.anchors.is_empty() => Err((None, err)),
        Err(err) => Err((Some(loader.store), err)),
        Ok(()) => Ok(loader.store),
    }
}
