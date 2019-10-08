/*!
	The new TCP- and UDP-based protocol.

	The protocol is designed to make full use of the mechanisms of the underlying protocols and be as simple as possible itself.

	Reliable packets are sent over TCP, which provides all necessary mechanisms for reliability and ordering. The only additional mechanism needed is message framing, as TCP is a stream-oriented protocol and doesn't have a concept of distinct messages. To implement this, each message is prefixed with a 32-bit length field (in bytes).

	Unreliable packets are sent over UDP, prefixed with an 8-bit ID for distinguishing between `Unreliable` (ID 0) and `UnreliableSequenced` (ID 1). In the case of `UnreliableSequenced`, a 32-bit sequence number is prefixed as well. To keep the protocol simple, no support for packet splitting is included, unreliable packets must be shorter than the MTU.
*/

use std::io;
use std::io::Result as Res;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};

use endio::LEWrite;

use crate::tls::Tls;

const ID_INTERNAL_PING: u8 = 0;
const ID_CONNECTED_PONG: u8 = 3;
const ID_DISCONNECTION_NOTIFICATION: u8 = 19;
const ID_CONNECTION_LOST: u8 = 20;
const PING_INTERVAL: u32 = 5000;
const MTU_SIZE: usize = 1228; // set by LU
const UDP_HEADER_SIZE: usize = 28;
const MAX_PACKET_SIZE: usize = MTU_SIZE - UDP_HEADER_SIZE;
static mut BUF: [u8; MAX_PACKET_SIZE] = [0; MAX_PACKET_SIZE];

pub const UNREL: u32 = 0;
pub const UNREL_SEQ: u32 = 1;
pub const REL_ORD: u32 = 3;

#[repr(C)]
pub struct RakPacket {
	system_index: u32,
	from_ip: [u8; 4],
	from_port: u16,
	byte_len: u32,
	bit_len: u32,
	pub data: *mut [u8],
	delete_data: bool,
}

trait ReliableTransport: std::io::Read+std::io::Write {
	fn local_addr(&self) -> Res<SocketAddr>;
	fn peer_addr(&self) -> Res<SocketAddr>;
	fn set_nonblocking(&self, nonblocking: bool) -> Res<()>;
}

impl ReliableTransport for TcpStream {
	fn local_addr(&self) -> Res<SocketAddr> { self.local_addr() }
	fn peer_addr(&self) -> Res<SocketAddr> { self.peer_addr() }
	fn set_nonblocking(&self, nonblocking: bool) -> Res<()> { self.set_nonblocking(nonblocking) }
}

impl ReliableTransport for Tls {
	fn local_addr(&self) -> Res<SocketAddr> { self.local_addr() }
	fn peer_addr(&self) -> Res<SocketAddr> { self.peer_addr() }
	fn set_nonblocking(&self, nonblocking: bool) -> Res<()> { self.set_nonblocking(nonblocking) }
}

/// Buffer for keeping packets that were only read in part.
struct BufferOffset {
	reading_length: bool,
	offset: usize,
	length: [u8; 4],
	buffer: Box<[u8]>,
}

#[derive(PartialEq)]
enum ConnState {
	Open,
	Disconnected,
	Lost,
}

pub struct Connection {
	tcp: Box<dyn ReliableTransport>,
	udp: UdpSocket,
	state: ConnState,
	ping_timer: u32,
	last_reliable_send_time: u32,
	last_ping: u32,
	cum_ping: u32,
	ping_count: u32,
	seq_num_recv: u32,
	seq_num_send: u32,
	packet: BufferOffset,
}

impl Connection {
	pub fn new(host: &str, port: u16) -> Res<Self> {
		let tcp: Box<dyn ReliableTransport> = if host == "localhost" || host == "127.0.0.1" {
			Box::new(TcpStream::connect((host, port))?)
		} else {
			Box::new(Tls::connect((host, port))?)
		};
		let udp = UdpSocket::bind(tcp.local_addr()?)?;
		udp.connect((host, port))?;
		tcp.set_nonblocking(true)?;
		udp.set_nonblocking(true)?;
		Ok(Connection {
			tcp,
			udp,
			state: ConnState::Open,
			ping_timer: 0,
			last_reliable_send_time: 0,
			last_ping: 0,
			cum_ping: 0,
			ping_count: 1,
			seq_num_recv: 0,
			seq_num_send: 0,
			packet: BufferOffset { reading_length: true, offset: 0, length: [0; 4], buffer: Box::new([]) },
		})
	}

	pub fn close(&mut self) {
		self.state = ConnState::Disconnected;
	}

	/// Send a packet.
	pub fn send(&mut self, data: &[u8], reliability: u32) -> Res<()> {
		match self.send_internal(data, reliability) {
			Ok(()) => Ok(()),
			Err(e) => {
				self.state = ConnState::Lost;
				Err(e)
			}
		}
	}

	fn send_internal(&mut self, data: &[u8], reliability: u32) -> Res<()> {
		match reliability {
			UNREL => {
				let mut vec = Vec::with_capacity(data.len()+1);
				vec.write(UNREL as u8)?;
				vec.write(data)?;
				self.udp.send(&vec)?;
			}
			UNREL_SEQ => {
				let seq_num = self.seq_num_send;
				self.seq_num_send = self.seq_num_send.wrapping_add(1);
				let mut vec = Vec::with_capacity(data.len()+1+4);
				vec.write(UNREL_SEQ as u8)?;
				vec.write(seq_num)?;
				vec.write(data)?;
				self.udp.send(&vec)?;
			}
			_ => {
				self.last_reliable_send_time = self.ping_timer;
				self.tcp.write(data.len() as u32)?;
				std::io::Write::write(&mut self.tcp, data)?;
			}
		}
		Ok(())
	}

	/// Try to receive a packet.
	pub fn receive(&mut self) -> Res<*const RakPacket> {
		let packet = self.receive_internal();
		if let Ok(p) = packet {
			if !p.is_null() {
				unsafe {
					if (*(*p).data)[0] == ID_INTERNAL_PING {
						let _ = self.send_pong(&(*(*p).data)[1..4]);
					} else if (*(*p).data)[0] == ID_CONNECTED_PONG {
						let _ = self.on_pong(&(*(*p).data)[1..]);
					}
				}
			}
		}
		packet
	}

	fn receive_internal(&mut self) -> Res<*const RakPacket> {
		if self.ping_timer - self.last_reliable_send_time > PING_INTERVAL {
			let _ = self.send_ping();
		}
		self.ping_timer = self.ping_timer.wrapping_add(20);

		if self.state == ConnState::Disconnected {
			self.state = ConnState::Open;
			return Ok(self.new_rak_packet(Box::new([ID_DISCONNECTION_NOTIFICATION])));
		} else if self.state == ConnState::Lost {
			self.state = ConnState::Open;
			return Ok(self.new_rak_packet(Box::new([ID_CONNECTION_LOST])));
		}

		match self.receive_tcp() {
			Ok(packet) => { return Ok(packet); },
			Err(err) => {
				if err.kind() != io::ErrorKind::WouldBlock {
					return Err(err);
				}
			}
		}
		match self.receive_udp() {
			Ok(packet) => { return Ok(packet); },
			Err(err) => {
				if err.kind() != io::ErrorKind::WouldBlock {
					return Err(err);
				}
			}
		}
		Ok(std::ptr::null())
	}

	fn new_rak_packet(&self, data: Box<[u8]>) -> *const RakPacket {
		let peer_addr = self.tcp.peer_addr().unwrap();
		let ip = match peer_addr.ip() {
			IpAddr::V4(ip) => ip,
			IpAddr::V6(ip) => {
				if ip.is_loopback() {
					Ipv4Addr::LOCALHOST
				} else {
					panic!()
				}
			}
		}.octets();

		Box::into_raw(Box::new(RakPacket {
			system_index: 0,
			from_ip: ip,
			from_port: peer_addr.port(),
			byte_len: data.len() as u32,
			bit_len: (data.len()*8) as u32,
			data: Box::into_raw(data),
			delete_data: true,
		}))
	}

	/// Try to receive a packet from UDP.
	fn receive_udp(&mut self) -> Res<*const RakPacket> {
		use endio::LERead;

		let len = self.udp.recv( unsafe {&mut BUF})?;
		let reader = unsafe { &mut &BUF[..] };
		let rel: u8 = reader.read()?;
		if rel == 0 {
			Ok(unsafe { self.new_rak_packet(Box::from(&BUF[1..len])) } )
		} else if rel == 1 {
			let seq_num: u32 = reader.read()?;
			if seq_num.wrapping_sub(self.seq_num_recv) < u32::max_value() / 2 {
				self.seq_num_recv = seq_num.wrapping_add(1);
				Ok(unsafe { self.new_rak_packet(Box::from(&BUF[5..len])) } )
			} else {
				Err(io::Error::new(io::ErrorKind::WouldBlock, "older sequenced packet"))
			}
		} else { panic!(); }
	}

	/// Try to receive a packet from TCP.
	fn receive_tcp(&mut self) -> Res<*const RakPacket> {
		use std::io::Read;

		if self.packet.reading_length {
			while self.packet.offset < self.packet.length.len() {
				let n = self.tcp.read(&mut self.packet.length[self.packet.offset..])?;
				if n == 0 {
					return Err(io::Error::new(io::ErrorKind::WouldBlock, "read zero"));
				}
				self.packet.offset += n;
			}
			self.packet.reading_length = false;
			self.packet.offset = 0;
			self.packet.buffer = vec![0; u32::from_le_bytes(self.packet.length) as usize].into_boxed_slice();
		}
		while self.packet.offset < self.packet.buffer.len() {
			let n = self.tcp.read(&mut self.packet.buffer[self.packet.offset..])?;
			self.packet.offset += n;
		}
		self.packet.reading_length = true;
		self.packet.offset = 0;
		let mut b = Box::from(&[][..]);
		std::mem::swap(&mut self.packet.buffer, &mut b);
		Ok(self.new_rak_packet(b))
	}

	fn send_ping(&mut self) -> Res<()> {
		let mut packet = [0; 5];
		let mut writer = &mut packet[..];
		writer.write(ID_INTERNAL_PING)?;
		writer.write(self.ping_timer)?;
		self.send(&packet, REL_ORD)
	}

	fn send_pong(&mut self, ping: &[u8]) -> Res<()> {
		let mut packet = [0; 9];
		let mut writer = &mut packet[..];
		writer.write(ID_CONNECTED_PONG)?;
		std::io::Write::write(&mut writer, ping)?;
		writer.write(0u32)?;
		self.send(&packet, REL_ORD)
	}

	fn on_pong(&mut self, pong: &[u8]) -> Res<()> {
		use endio::LERead;
		let reader = &mut &pong[..];
		let current_time = self.ping_timer;
		let old_time: u32 = reader.read()?;
		self.last_ping = current_time - old_time;
		self.cum_ping += self.last_ping;
		self.ping_count += 1;
		Ok(())
	}

	pub fn last_ping(&self) -> u32 {
		self.last_ping
	}

	pub fn average_ping(&self) -> u32 {
		self.cum_ping / self.ping_count
	}
}
