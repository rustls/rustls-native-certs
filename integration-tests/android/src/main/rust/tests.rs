#[allow(non_snake_case)]
pub mod android {
    extern crate android_log_sys as android_log;
    extern crate jni;
    extern crate rustls;
    extern crate rustls_native_certs;
    extern crate untrusted;
    extern crate webpki;

    use jni::objects::{JObject, JString};
    use jni::JNIEnv;
    use ring::io::der;
    use rustls::pki_types::Der;
    use std::collections::HashMap;
    use std::ffi::CString;
    use std::io::{ErrorKind, Read, Write};
    use std::net::TcpStream;
    use std::sync::Arc;
    use webpki::anchor_from_trusted_cert;

    #[no_mangle]
    pub unsafe extern "C" fn Java_rustls_android_tests_CompareMozilla_test_1does_1not_1have_1many_1roots_1unknown_1by_1mozilla<
        'local,
    >(
        mut env: JNIEnv<'local>,
        _this: JObject<'local>,
    ) -> JObject<'local> {
        let native = rustls_native_certs::load_native_certs();
        let mozilla = webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .map(|ta| (ta.subject_public_key_info.as_ref(), ta))
            .collect::<HashMap<_, _>>();

        let mut missing_in_moz_roots = 0;

        for cert in &native.certs {
            let cert = anchor_from_trusted_cert(cert).unwrap();
            if let Some(moz) = mozilla.get(cert.subject_public_key_info.as_ref()) {
                if assert(
                    &mut env,
                    *cert.subject == *moz.subject,
                    Some("subjects differ for public key"),
                ) {
                    return JObject::null();
                }
            } else {
                log(
                    TAG,
                    format!(
                        "Native anchor {:?} is missing from mozilla set",
                        stringify_x500name(&cert.subject)
                    )
                    .as_str(),
                );
                missing_in_moz_roots += 1;
            }
        }

        #[cfg(target_os = "android")]
        let threshold = 0.3; // no more than 30% extra roots;

        let diff = (missing_in_moz_roots as f64) / (mozilla.len() as f64);
        log(TAG, format!("mozilla: {:?}", mozilla.len()).as_str());
        log(TAG, format!("native: {:?}", native.certs.len()).as_str());
        log(
            TAG,
            format!(
                "{:?} anchors present in native set but not mozilla ({}%)",
                missing_in_moz_roots,
                diff * 100.
            )
            .as_str(),
        );

        assert(&mut env, diff < threshold, Some("too many missing roots"));

        return JObject::null();
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_rustls_android_tests_CompareMozilla_test_1contains_1most_1roots_1known_1by_1mozilla<
        'local,
    >(
        mut env: JNIEnv<'local>,
        _this: JObject<'local>,
    ) -> JObject<'local> {
        let native = rustls_native_certs::load_native_certs();

        let mut native_map = HashMap::new();
        for anchor in &native.certs {
            let cert = anchor_from_trusted_cert(anchor).unwrap();
            let spki = cert.subject_public_key_info.as_ref();
            native_map.insert(spki.to_owned(), anchor);
        }

        let mut missing_in_native_roots = 0;
        let mozilla = webpki_roots::TLS_SERVER_ROOTS;
        for cert in mozilla {
            if !native_map.contains_key(cert.subject_public_key_info.as_ref()) {
                log(
                    TAG,
                    format!(
                        "Mozilla anchor {:?} is missing from native set",
                        stringify_x500name(&cert.subject)
                    )
                    .as_str(),
                );
                missing_in_native_roots += 1;
            }
        }

        #[cfg(target_os = "android")]
        let threshold = 0.3; // no more than 30% extra roots;

        let diff = (missing_in_native_roots as f64) / (mozilla.len() as f64);
        log(TAG, format!("mozilla: {:?}", mozilla.len()).as_str());
        log(TAG, format!("native: {:?}", native.certs.len()).as_str());
        log(
            TAG,
            format!(
                "{:?} anchors present in mozilla set but not native ({}%)",
                missing_in_native_roots,
                diff * 100.
            )
            .as_str(),
        );

        assert(&mut env, diff < threshold, Some("too many missing roots"));

        return JObject::null();
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_rustls_android_tests_CompareMozilla_util_1list_1certs<'local>(
        mut _env: JNIEnv<'local>,
        _this: JObject<'local>,
    ) -> JObject<'local> {
        let native = rustls_native_certs::load_native_certs();
        for (i, cert) in native.certs.iter().enumerate() {
            let cert = anchor_from_trusted_cert(cert).unwrap();
            log(
                TAG,
                format!("cert[{i}] = {}", stringify_x500name(&cert.subject)).as_str(),
            );
        }
        return JObject::null();
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_rustls_android_tests_SmokeTests_check_1site<'local>(
        mut env: JNIEnv<'local>,
        _this: JString<'local>,
        domain: JString<'local>,
    ) -> JObject<'local> {
        let domain_string = env.get_string(&domain).unwrap();
        let domain_str = domain_string.to_str().unwrap();
        let _ = check_site(&mut env, domain_str);
        return JObject::null();
    }

    fn stringify_x500name(subject: &Der<'_>) -> String {
        let mut parts = vec![];
        let mut reader = untrusted::Reader::new(subject.as_ref().into());

        while !reader.at_end() {
            let (tag, contents) = der::read_tag_and_get_value(&mut reader).unwrap();
            assert!(tag == 0x31); // sequence, constructed, context=1

            let mut inner = untrusted::Reader::new(contents);
            let pair = der::expect_tag_and_get_value(&mut inner, der::Tag::Sequence).unwrap();

            let mut pair = untrusted::Reader::new(pair);
            let oid = der::expect_tag_and_get_value(&mut pair, der::Tag::OID).unwrap();
            let (valuety, value) = der::read_tag_and_get_value(&mut pair).unwrap();

            let name = match oid.as_slice_less_safe() {
                [0x55, 0x04, 0x03] => "CN",
                [0x55, 0x04, 0x05] => "serialNumber",
                [0x55, 0x04, 0x06] => "C",
                [0x55, 0x04, 0x07] => "L",
                [0x55, 0x04, 0x08] => "ST",
                [0x55, 0x04, 0x09] => "STREET",
                [0x55, 0x04, 0x0a] => "O",
                [0x55, 0x04, 0x0b] => "OU",
                [0x55, 0x04, 0x11] => "postalCode",
                [0x55, 0x04, 0x61] => "organizationIdentifier",
                [0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19] => "domainComponent",
                [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01] => "emailAddress",
                _ => panic!("unhandled x500 attr {:?}", oid),
            };

            let str_value = match valuety {
                // PrintableString, UTF8String, TeletexString or IA5String
                0x0c | 0x13 | 0x14 | 0x16 => {
                    std::str::from_utf8(value.as_slice_less_safe()).unwrap()
                }
                _ => panic!("unhandled x500 value type {:?}", valuety),
            };

            parts.push(format!("{}={}", name, str_value));
        }

        parts.join(", ")
    }

    fn check_site(env: &mut JNIEnv, domain: &str) -> Result<(), ()> {
        check_site_with_roots(
            env,
            domain,
            rustls_native_certs::load_native_certs().unwrap(),
        )
    }

    fn check_site_with_roots(
        env: &mut JNIEnv,
        domain: &str,
        root_certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    ) -> Result<(), ()> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add_parsable_certificates(root_certs);

        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        let mut alpn = Vec::<String>::new();
        alpn.push("http/1.1".to_string());
        config.alpn_protocols = alpn
            .iter()
            .map(|proto| proto.as_bytes().to_vec())
            .collect();

        let mut conn = rustls::ClientConnection::new(
            Arc::new(config),
            rustls::pki_types::ServerName::try_from(domain)
                .unwrap()
                .to_owned(),
        )
        .unwrap();
        let mut sock = TcpStream::connect(format!("{}:443", domain)).unwrap();
        let mut tls = rustls::Stream::new(&mut conn, &mut sock);
        let request = format!(
            "GET / HTTP/1.1\r\n\
                       Host: {}\r\n\
                       Connection: close\r\n\
                       Accept-Encoding: identity\r\n\
                       \r\n",
            domain
        );

        log(TAG, "REQUEST >>>>>>>>>>>>>");
        log(TAG, request.as_str());
        let result = tls.write_all(request.as_bytes());
        match result {
            Ok(()) => (),
            Err(e) if e.kind() == ErrorKind::InvalidData => {
                panic(env, format!("{:?}", e).as_str());
                return Err(());
            } // TLS error
            Err(e) => {
                panic(env, format!("{:?}", e).as_str());
                return Err(());
            }
        }

        let mut plaintext = [0u8; 64];
        let len = tls.read(&mut plaintext); //.unwrap();
        log(TAG, format!("read {:?}", len).as_str());
        // log(TAG, "RESPONSE <<<<<<<<<<<<<");
        // // log(TAG, &String::from_utf8_lossy(&plaintext[..len]));
        // log(TAG, format!("{:?}", &plaintext[..len]).as_str());
        // assert(env, plaintext[..len].starts_with(b"HTTP/1.1 "), None); // or whatever
        Ok(())
    }

    const DEFAULT_PRIO: android_log::c_int =
        android_log::LogPriority::DEFAULT as android_log::c_int;
    const TAG: &str = "RUSTLS_NATIVE_CERTS";
    fn log(tag: &str, msg: &str) {
        let c_prio = android_log::LogPriority::DEBUG as android_log::c_int;
        let c_tag = CString::new(tag).unwrap().into_raw();
        unsafe {
            if android_log::__android_log_is_loggable(c_prio, c_tag, DEFAULT_PRIO) != 0 {
                let c_msg = CString::new(msg).unwrap().into_raw();
                android_log::__android_log_print(c_prio, c_tag, c_msg);
            }
        };
    }

    pub fn assert<'local>(env: &mut JNIEnv<'local>, test: bool, msg: Option<&str>) -> bool {
        if env.exception_check().unwrap() {
            env.exception_clear().unwrap();
        }
        if !test {
            let clazz = env
                .find_class("java/lang/AssertionError")
                .unwrap();
            match msg {
                Some(msg) => env.throw_new(clazz, msg).unwrap(),
                None => env.throw_new(clazz, "").unwrap(),
            }
        }
        return !test;
    }

    pub fn panic<'local>(env: &mut JNIEnv<'local>, msg: &str) {
        if env.exception_check().unwrap() {
            env.exception_clear().unwrap();
        }
        let clazz = env
            .find_class("java/lang/Error")
            .unwrap();
        env.throw_new(clazz, msg).unwrap();
    }
}
