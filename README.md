![Logo](https://raw.githubusercontent.com/ctz/rustls/master/admin/rustls-logo-web.png)

**rustls-native-certs** allows [rustls](https://github.com/ctz/rustls) to use the
platform's native certificate store when operating as a TLS client.

This is supported on Windows, macOS and Linux:

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

[![Build Status](https://dev.azure.com/ctz99/ctz/_apis/build/status/ctz.rustls-native-certs?branchName=master)](https://dev.azure.com/ctz99/ctz/_build/latest?definitionId=5&branchName=master)

## Release history:

* Next release:
  - Initial release.

# API

This library exposes a single function with this signature:

```rust
pub fn load_native_certs() -> Result<rustls::RootCertStore, std::io::Error>
```

On success, this returns a `rustls::RootCertStore` loaded with a
snapshop of the root certificates found on this platform.  This
function fails in a platform-specific way, expressed in a `std::io::Error`.

This function can be expensive: on some platforms it involves loading
and parsing a ~300KB disk file.  It's therefore prudent to call
this sparingly.

# Example

(...)

# License

rustls-native-certs is distributed under the following three licenses:

- Apache License version 2.0.
- MIT license.
- ISC license.

These are included as LICENSE-APACHE, LICENSE-MIT and LICENSE-ISC
respectively.  You may use this software under the terms of any
of these licenses, at your option.
