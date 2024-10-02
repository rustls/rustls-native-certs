![Logo](https://raw.githubusercontent.com/rustls/rustls/main/admin/rustls-logo-web.png)

**rustls-native-certs** allows [rustls](https://github.com/rustls/rustls) to use the
platform's native certificate store when operating as a TLS client.

This is supported on Windows, macOS and Linux:

- On all platforms, the `SSL_CERT_FILE` environment variable is checked first.
  If that's set, certificates are loaded from the path specified by that variable,
  or an error is returned if certificates cannot be loaded from the given path.
  If it's not set, then the platform-specific certificate source is used.
- On Windows, certificates are loaded from the system certificate store.
  The [`schannel`](https://github.com/steffengy/schannel-rs) crate is used to access
  the Windows certificate store APIs.
- On macOS, certificates are loaded from the keychain.
  The user, admin and system trust settings are merged together as documented
  by Apple.  The [`security-framework`](https://github.com/kornelski/rust-security-framework)
  crate is used to access the keystore APIs.
- On Linux and other UNIX-like operating systems, the
  [`openssl-probe`](https://github.com/alexcrichton/openssl-probe) crate is used to discover
  the filename of the system CA bundle.

# Status
rustls-native-certs is currently in development.

If you'd like to help out, please see [CONTRIBUTING.md](CONTRIBUTING.md).

[![rustls](https://github.com/rustls/rustls-native-certs/actions/workflows/rust.yml/badge.svg)](https://github.com/rustls/rustls-native-certs/actions/workflows/rust.yml)
[![Documentation](https://docs.rs/rustls-native-certs/badge.svg)](https://docs.rs/rustls-native-certs)

## Release history:

* 0.7.0 (2023-12-03)
  - Switched to using the [pki-types](https://github.com/rustls/pki-types) crate.
    - `load_native_certs` now returns `Vec<pki_types::CertificateDer<'static>>` instead of `Vec<Certificate>`
    - the `Certificate` newtype has been removed.
  - Update dependencies.
* 0.6.3 (2023-06-14)
  - Bump MSRV to 1.60.
  - Windows: avoid storing certificates which are currently invalid.
  - Implement `AsRef<[u8]>` for `Certificate`.
* 0.6.2 (2022-04-14):
  - Update dependencies.
* 0.6.1 (2021-10-25):
  - Allow overrides using `SSL_CERT_FILE` on all platforms.
* 0.6.0 (2021-10-24):
  - Remove rustls dependency entirely.
* 0.5.0 (2020-11-22):
  - Update dependencies.
  - Make rustls dependency optional, for use with reqwest's certificate types.  Thanks to @est31.
* 0.4.0 (2020-07-05):
  - Update dependencies.
* 0.3.0 (2020-02-24):
  - Support wider range of UNIX platforms.
  - Update dependencies.
* 0.2.0 (2020-01-26):
  - Return valid certificates even in the presence of invalid ones.  This allows
    callers to opt-in to "best effort" behaviour.
* 0.1.0 (2019-11-04):
  - Initial release.

# API

This library exposes a single function with this signature:

```rust
pub fn load_native_certs() -> Result<Vec<pki_types::CertificateDer<'static>>, std::io::Error>
```

On success, this returns a `Vec<pki_types::CertificateDer<'static>>` loaded with a
snapshot of the root certificates found on this platform.  This
function fails in a platform-specific way, expressed in a `std::io::Error`.

This function can be expensive: on some platforms it involves loading
and parsing a ~300KB disk file.  It's therefore prudent to call
this sparingly.

# Worked example

See [`examples/google.rs`](examples/google.rs).

# Should I use this or `webpki-roots`?

(Background: [webpki-roots](https://crates.io/crates/webpki-roots) is a crate that compiles-in Mozilla's set of root certificates.)

Please see `rustls-platform-verifier`'s documentation on [deployment considerations](https://github.com/rustls/rustls-platform-verifier?tab=readme-ov-file#deployment-considerations) for more info.

Additionally in most cases, the platform verifier is a better option than this crate if you are already considering `rustls-native-certs`.

# License

rustls-native-certs is distributed under the following three licenses:

- Apache License version 2.0.
- MIT license.
- ISC license.

These are included as LICENSE-APACHE, LICENSE-MIT and LICENSE-ISC
respectively.  You may use this software under the terms of any
of these licenses, at your option.
