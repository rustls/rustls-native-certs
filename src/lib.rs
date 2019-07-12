#[cfg_attr(target_os = "linux", path = "linux.rs")]
#[cfg_attr(target_family = "windows", path = "windows.rs")]
#[cfg_attr(target_os = "macos", path = "macos.rs")]
mod platform;

pub use platform::load_native_certs;
