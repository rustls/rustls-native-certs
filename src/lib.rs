//! rustls-native-certs allows rustls to use the platform's native certificate
//! store when operating as a TLS client.
//!
//! It consists of a single function [load_native_certs](fn.load_native_certs.html) which returns a
//! `rustls::RootCertStore` pre-filled from the native certificate store.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as platform;

#[cfg(target_family = "windows")]
mod windows;
#[cfg(target_family = "windows")]
use windows as platform;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as platform;

pub use platform::load_native_certs;
