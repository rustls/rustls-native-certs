extern crate jni;

use crate::CertificateResult;
use jni::errors::Error;
use jni::objects::{JByteArray, JObject, JString, JValue};
use jni::sys::JavaVM as JavaVMSys;
use jni::sys::{jint, jsize, JNI_OK};
use jni::{AttachGuard, JavaVM};
use pki_types::CertificateDer;
use std::fmt::{Debug, Display, Formatter};

pub type JniGetCreatedJavaVms = unsafe extern "system" fn(
    vm_buf: *mut *mut jni::sys::JavaVM,
    buf_len: jsize,
    n_vms: *mut jsize,
) -> jint;

pub fn load_native_certs() -> CertificateResult {
    let mut result = CertificateResult::default();

    // Get a JVM
    let jvm = match get_jvm() {
        Ok(jvm) => jvm,
        Err(err) => {
            result.errors.push(err);
            return result;
        }
    };

    // Get a JVM environment
    let mut env = match jvm.attach_current_thread() {
        Ok(env) => env,
        Err(err) => {
            result.errors.push(From::from(err));
            return result;
        }
    };

    // Load the Android keystore
    let mut keystore = match get_key_store(&mut env) {
        Ok(keystore) => keystore,
        Err(err) => {
            result.errors.push(err);
            return result;
        }
    };

    // Extract any certificates in the keystore
    if let Err(err) = extract_certificates(&mut env, &mut keystore, &mut result) {
        result.errors.push(err);
        return result;
    };

    // Clear any JNI exception as any error is returned via CertificateResult
    if env.exception_check().is_ok() {
        let _ = env.exception_clear();
    }

    result
}

fn get_jvm() -> Result<JavaVM, crate::Error> {
    let library = libloading::os::unix::Library::this();
    let fn_get_created_java_vms: JniGetCreatedJavaVms =
        unsafe { *library.get(b"JNI_GetCreatedJavaVMs")? };
    let mut created_java_vms: [*mut JavaVMSys; 1] = [std::ptr::null_mut() as *mut JavaVMSys];
    let mut vms_read: i32 = 0;
    match unsafe { fn_get_created_java_vms(created_java_vms.as_mut_ptr(), 1, &mut vms_read) } {
        JNI_OK => {}
        x => {
            let context = format!("Failed to obtain JVM reference [code: {}]", x).to_string();
            Err(FFIError::new(context))?
        }
    };
    let jvm_ptr = match created_java_vms.first() {
        Some(ptr) => *ptr,
        None => Err(FFIError::new("No JVM created".to_string()))?,
    };
    Ok(unsafe { JavaVM::from_raw(jvm_ptr) }?)
}

fn get_key_store<'a>(env: &mut AttachGuard<'a>) -> Result<JObject<'a>, crate::Error> {
    let clazz = env.find_class("java/security/KeyStore")?;
    let keystore_name = &JObject::from(env.new_string("AndroidCAStore")?);
    let args = &[JValue::Object(keystore_name)];
    let keystore = env
        .call_static_method(
            clazz,
            "getInstance",
            "(Ljava/lang/String;)Ljava/security/KeyStore;",
            args,
        )?
        .l()?;

    let null = JObject::null();
    let args = &[JValue::Object(&null)];
    let _ = &env
        .call_method(
            &keystore,
            "load",
            "(Ljava/security/KeyStore$LoadStoreParameter;)V",
            args,
        )?
        .v()?;

    Ok(keystore)
}

fn extract_certificates<'a>(
    env: &mut AttachGuard<'a>,
    keystore: &mut JObject,
    result: &mut CertificateResult,
) -> Result<(), crate::Error> {
    // Enumerate each certificate alias in the keystore
    let enumeration = &env
        .call_method(&keystore, "aliases", "()Ljava/util/Enumeration;", &[])?
        .l()?;
    loop {
        // Check if there are more aliases
        if !env
            .call_method(enumeration, "hasMoreElements", "()Z", &[])?
            .z()?
        {
            break;
        }

        // Get the certificate alias
        let alias = env
            .call_method(enumeration, "nextElement", "()Ljava/lang/Object;", &[])?
            .l()?;

        // Read the certificate
        read_certificate(env, keystore, alias, result);
    }
    Ok(())
}

fn read_certificate<'a>(
    env: &mut AttachGuard<'a>,
    keystore: &mut JObject,
    alias: JObject,
    result: &mut CertificateResult,
) {
    let alias_jstring = JString::from(alias);
    let alias_str = match env.get_string(&alias_jstring) {
        Ok(value) => value
            .to_str()
            .unwrap_or_else(|_| "unknown")
            .to_string(),
        Err(_) => "unknown".to_string(),
    };
    let args = &[JValue::Object(&alias_jstring)];
    let ret = env.call_method(
        keystore,
        "getCertificate",
        "(Ljava/lang/String;)Ljava/security/cert/Certificate;",
        args,
    );
    let certificate = match ret {
        Ok(value) => match value.l() {
            Ok(cert) => cert,
            Err(err) => {
                let context = format!("Failed to read certificate. Alias: {}", alias_str);
                result
                    .errors
                    .push(From::from(FFIError::new_with_source(context, err)));
                return;
            }
        },
        Err(err) => {
            let context = format!("Failed to read certificate. Alias: {}", alias_str);
            result
                .errors
                .push(From::from(FFIError::new_with_source(context, err)));
            return;
        }
    };

    // Get the der encoded bytes
    let ret = env.call_method(certificate, "getEncoded", "()[B", &[]);
    let der_object = match ret {
        Ok(value) => match value.l() {
            Ok(der_object) => der_object,
            Err(err) => {
                let context = format!("Failed to decode certificate. Alias: {}", alias_str);
                result
                    .errors
                    .push(From::from(FFIError::new_with_source(context, err)));
                return;
            }
        },
        Err(err) => {
            let context = format!("Failed to decode certificate. Alias: {}", alias_str);
            result
                .errors
                .push(From::from(FFIError::new_with_source(context, err)));
            return;
        }
    };

    // Get the amount of bytes
    let der_byte_array = JByteArray::from(der_object);
    let length = match env.get_array_length(&der_byte_array) {
        Ok(size) => size as usize,
        Err(err) => {
            let context = format!("Failed to decode certificate. Alias: {}", alias_str);
            result
                .errors
                .push(From::from(FFIError::new_with_source(context, err)));
            return;
        }
    };

    // Read from JNI ByteArray to rust Vec<i8>
    let mut der_encoded_data: Vec<i8> = vec![0; length];
    match env.get_byte_array_region(der_byte_array, 0, &mut der_encoded_data) {
        Ok(_) => {}
        Err(err) => {
            let context = format!("Failed to decode certificate. Alias: {}", alias_str);
            result
                .errors
                .push(From::from(FFIError::new_with_source(context, err)));
            return;
        }
    };

    // Transform from i8 to u8 and store the certificate
    let certificate_der = CertificateDer::from(
        unsafe { &*(der_encoded_data.as_slice() as *const _ as *const [u8]) }.to_owned(),
    );
    result.certs.push(certificate_der);
}

#[derive(Debug)]
struct FFIError {
    context: String,
    source: Option<jni::errors::Error>,
}
impl FFIError {
    fn new_with_source(context: String, source: jni::errors::Error) -> Self {
        FFIError {
            context,
            source: Some(source),
        }
    }

    fn new(context: String) -> Self {
        FFIError {
            context,
            source: None,
        }
    }
}
impl std::error::Error for FFIError {}
impl Display for FFIError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.context)
    }
}

impl From<FFIError> for crate::Error {
    fn from(value: FFIError) -> Self {
        crate::Error {
            context: "Foreign Function operation failed",
            kind: match value.source {
                Some(error) => crate::ErrorKind::Os(Box::new(error)),
                None => crate::ErrorKind::Os(Box::new(value)),
            },
        }
    }
}
impl From<libloading::Error> for crate::Error {
    fn from(value: libloading::Error) -> Self {
        crate::Error {
            context: "Failed to load library",
            kind: crate::ErrorKind::Os(Box::new(value)),
        }
    }
}
impl From<jni::errors::Error> for crate::Error {
    fn from(value: Error) -> Self {
        crate::Error {
            context: "Jni operation failed",
            kind: crate::ErrorKind::Os(Box::new(value)),
        }
    }
}
