use std::sync::Arc;

use std::net::TcpStream;
use std::io::{Read, Write};

use rustls;
use webpki;
use rustls_native_certs;

#[test]
fn google_smoketest() -> Result<(), std::io::Error> {
    let mut config = rustls::ClientConfig::new();
    config.root_store = rustls_native_certs::load_native_certs()?;
    println!("we have {} root certs", config.root_store.len());

    let dns_name = webpki::DNSNameRef::try_from_ascii_str("google.com").unwrap();
    let mut sess = rustls::ClientSession::new(&Arc::new(config), dns_name);
    let mut sock = TcpStream::connect("google.com:443").unwrap();
    let mut tls = rustls::Stream::new(&mut sess, &mut sock);
    tls.write(concat!("GET / HTTP/1.1\r\n",
                      "Host: google.com\r\n",
                      "Connection: close\r\n",
                      "Accept-Encoding: identity\r\n",
                      "\r\n")
              .as_bytes())
        .unwrap();
    let mut plaintext = Vec::new();
    tls.read_to_end(&mut plaintext).unwrap();
    assert!(plaintext.starts_with(b"HTTP/1.1 ")); // or whatever
    Ok(())
}
