use crate::Certificate;

use std::io::Error;

use windows_sys::Win32::{
    Foundation::{CRYPT_E_NOT_FOUND, FILETIME, S_OK},
    Security::Cryptography::{self, CERT_CONTEXT, CTL_USAGE},
    System::{SystemInformation::GetSystemTime, Time::SystemTimeToFileTime},
};

static PKIX_SERVER_AUTH: &[u8] = b"1.3.6.1.5.5.7.3.1\0";
const STORES: [u32; 6] = [
    Cryptography::CERT_SYSTEM_STORE_CURRENT_USER_ID,
    Cryptography::CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY_ID,
    Cryptography::CERT_SYSTEM_STORE_LOCAL_MACHINE_ID,
    Cryptography::CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE_ID,
    Cryptography::CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY_ID,
    Cryptography::CERT_SYSTEM_STORE_CURRENT_SERVICE_ID,
];

pub fn load_native_certs() -> Result<Vec<Certificate>, Error> {
    let mut certs = Vec::new();

    let time = unsafe { get_file_time() };
    let time = if let Ok(time) = &time {
        time
    } else {
        core::ptr::null()
    };

    let mut error = None;
    for store in STORES {
        if let Err(e) = unsafe { load_cert_store(&mut certs, store, time) } {
            //eprintln!(concat!(file!(), ":", line!(), ": certificate store failed: {}"), store);
            error = Some(e);
        }
    }

    if certs.is_empty() {
        if let Some(e) = error {
            return Err(e);
        }
    }

    Ok(certs)
}

/// Get the current time in what windows calls `FILETIME`.
unsafe fn get_file_time() -> Result<windows_sys::Win32::Foundation::FILETIME, Error> {
    let mut sys_time = core::mem::MaybeUninit::uninit();
    GetSystemTime(sys_time.as_mut_ptr());
    let mut filetime = core::mem::MaybeUninit::uninit();
    if SystemTimeToFileTime(sys_time.as_ptr(), filetime.as_mut_ptr()) != 0 {
        Ok(filetime.assume_init())
    } else {
        Err(Error::last_os_error())
    }
}

/// Load certificates from a windows certificate store. Avoids duplicates and invalid certs.
unsafe fn load_cert_store(
    certs: &mut Vec<Certificate>,
    system_store: u32,
    filetime: *const FILETIME,
) -> Result<(), Error> {
    let dw_flags = Cryptography::CERT_STORE_READONLY_FLAG
        | (system_store << Cryptography::CERT_SYSTEM_STORE_LOCATION_SHIFT);

    /// null ended UTF-16le string "ROOT"
    const ROOT: &[u8; 10] = b"R\0O\0O\0T\0\0\0";
    const ALIGN: usize = core::mem::align_of::<CTL_USAGE>();

    // https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certopenstore
    let store = Cryptography::CertOpenStore(
        Cryptography::CERT_STORE_PROV_SYSTEM_W,
        0,
        0,
        dw_flags,
        ROOT as *const _ as *mut _,
    );
    if store.is_null() {
        return Err(Error::last_os_error());
    }

    let mut cert_context: *mut CERT_CONTEXT = core::ptr::null_mut();
    let mut alloc: *mut u8 = core::ptr::null_mut();
    let mut alloc_size = 0usize;

    loop {
        // enumerate each cert in store
        cert_context = Cryptography::CertEnumCertificatesInStore(store, cert_context);
        if cert_context.is_null() {
            break;
        }

        let ctx = &*cert_context;
        let cert_info = &*ctx.pCertInfo;

        // skip certificates that are no longer/not yet valid
        // https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certverifytimevalidity
        if Cryptography::CertVerifyTimeValidity(filetime, cert_info) != 0 {
            continue;
        }

        // check allowed usages
        // https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certgetenhancedkeyusage
        let mut data_size = 0;
        #[allow(unreachable_code)]
        if Cryptography::CertGetEnhancedKeyUsage(ctx, 0, core::ptr::null_mut(), &mut data_size) == 0
        {
            // this would always have panicked previously, but just skip the cert if this happens in release
            #[cfg(debug_assertions)]
            panic!("{}", Error::last_os_error());
            continue;
        }
        {
            let data_size = data_size as usize;
            // allocate the needed space
            if data_size > alloc_size {
                if !alloc.is_null() {
                    std::alloc::dealloc(
                        alloc,
                        std::alloc::Layout::from_size_align_unchecked(alloc_size, ALIGN),
                    );
                }
                alloc = std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
                    data_size, ALIGN,
                ));
                alloc_size = data_size;
            }
        }
        let pusage = alloc as *mut () as *mut CTL_USAGE;
        #[allow(unreachable_code)]
        if Cryptography::CertGetEnhancedKeyUsage(ctx, 0, pusage, &mut data_size) == 0 {
            // this would always have panicked previously, but just skip the cert if this happens in release
            #[cfg(debug_assertions)]
            panic!("{}", Error::last_os_error());
            continue;
        }
        let pusage = &*pusage;
        let mut usages = pusage.cUsageIdentifier as isize;
        if usages == 0 {
            // returning key usage failed either because all usages are allowed or none
            let err = Error::last_os_error();
            let raw = err.raw_os_error();
            if raw != Some(CRYPT_E_NOT_FOUND) {
                #[cfg(debug_assertions)]
                if raw != Some(S_OK) {
                    // this would always have panicked previously, but just skip the cert if this happens in release
                    panic!("{}", err);
                }
                continue;
            }
        } else {
            let mut matched = false;
            'usages: while usages != 0 {
                usages -= 1;
                let mut item = *pusage
                    .rgpszUsageIdentifier
                    .offset(usages);
                for b in PKIX_SERVER_AUTH {
                    if *b != *item {
                        continue 'usages;
                    }
                    item = item.offset(1);
                }
                matched = true;
                break;
            }
            if !matched {
                continue;
            }
        }

        let der = core::slice::from_raw_parts(ctx.pbCertEncoded, ctx.cbCertEncoded as usize);

        if certs.iter().any(|x| x.0 == der) {
            // already added
            continue;
        }

        //eprintln!(concat!(file!(), ":", line!(), ": added cert from store {system_store}"));

        // add the certificate
        certs.push(Certificate(der.to_vec()));
    }

    // clean up allocation
    if !alloc.is_null() {
        std::alloc::dealloc(
            alloc,
            std::alloc::Layout::from_size_align_unchecked(alloc_size, ALIGN),
        );
    }

    // close windows cert store
    Cryptography::CertCloseStore(store, 0);

    Ok(())
}
