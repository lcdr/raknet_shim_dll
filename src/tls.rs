/*!
	Alternative drop-in TCP replacement with TLS encryption.
*/
use std::io;
use std::io::{Read, Write};
use std::io::Result as Res;
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;

use rustls::Session;

struct NoVerification {}

impl rustls::ServerCertVerifier for NoVerification {
	fn verify_server_cert(&self, _roots: &rustls::RootCertStore, _certs: &[rustls::Certificate], _hostname: webpki::DNSNameRef<'_>, _ocsp: &[u8]) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
		Ok(rustls::ServerCertVerified::assertion())
	}
}

pub struct Tcp {
	stream: rustls::StreamOwned<rustls::ClientSession, TcpStream>,
}

impl Tcp {
	pub fn connect(addr: (&str, u16)) -> Res<Self> {
		let (host, port) = addr;
		let mut config = rustls::ClientConfig::new();
		if host == "localhost" {
			// allow self-signed certificates on localhost
			config.dangerous().set_certificate_verifier(Arc::new(NoVerification {}));
		} else {
			config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
		}

		let dns_name = match webpki::DNSNameRef::try_from_ascii_str(host) {
			Ok(d) => d,
			Err(_) => { return Err(io::Error::new(io::ErrorKind::InvalidInput, "Host is not a valid DNS name. IPs are not supported for TLS. (localhost is ok though)")); }
		};
		let sess = rustls::ClientSession::new(&Arc::new(config), dns_name);
		let sock = TcpStream::connect((host, port))?;
		sock.set_nonblocking(true)?;

		let mut stream = rustls::StreamOwned::new(sess, sock);

		while stream.sess.is_handshaking() {
			while let Err(e) = stream.sess.complete_io(&mut stream.sock) {
				if e.kind() != std::io::ErrorKind::WouldBlock {
					return Err(e);
				}
				std::thread::sleep(std::time::Duration::from_millis(30));
			}
		}

		Ok(Tcp { stream } )
	}

	pub fn local_addr(&self) -> Res<SocketAddr> {
		self.stream.sock.local_addr()
	}

	pub fn peer_addr(&self) -> Res<SocketAddr> {
		self.stream.sock.peer_addr()
	}

	pub fn set_nonblocking(&self, nonblocking: bool) -> Res<()> {
		self.stream.sock.set_nonblocking(nonblocking)
	}
}

impl Read for Tcp {
	fn read(&mut self, buf: &mut [u8]) -> Res<usize> {
		self.stream.read(buf)
	}
}

impl Write for Tcp {
	fn write(&mut self, buf: &[u8]) -> Res<usize> {
		self.stream.write(buf)
	}

	fn flush(&mut self) -> Res<()> {
		self.stream.flush()
	}
}
