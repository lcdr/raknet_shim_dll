use std::ffi::CStr;
use std::io::Result as Res;
use std::os::raw::{c_char, c_uchar};
use std::ptr;
use winapi::shared::minwindef::LPVOID;

use crate::detour::{detour, patch_byte};
use crate::tcpudp::{Connection, RakPacket, REL_ORD};

const RAK_CLOSE_CONNECTION: usize = 0x643e60;
const RAK_CONNECT: usize = 0x6409f0;
const RAK_DEALLOCATE_PACKET: usize = 0x63e6c0;
const RAK_GET_AVERAGE_PING: usize = 0x640540;
const RAK_GET_LAST_PING: usize = 0x640500;
const RAK_RECEIVE: usize = 0x644610;
const RAK_SEND: usize = 0x63f540;
const RAK_SHUTDOWN: usize = 0x641dc0;
const RAK_STARTUP: usize = 0x645e40;
const CLOSE_CONNECT_PARAM: usize = 0x7332b8;

const STOP_PROCESSING_AND_DEALLOCATE: u32 = 0;
const STOP_PROCESSING: u32 = 2;

const MTU: *mut Connection = 1228 as *mut Connection; // original MTU value, if this is present it means we haven't hijacked the MTU field yet

fn set_conn(this: usize, conn: *mut Connection) {
	unsafe { *((this+0xc14) as *mut *mut Connection) = conn }
}

fn get_conn(this: usize) -> *mut Connection {
	unsafe { *((this+0xc14) as *mut *mut Connection) }
}

unsafe extern "thiscall" fn new_close_connection(this: usize, ip: u32, port: u16, send_notification: bool, _ordering_channel: u8) {
	let conn = get_conn(this);
	if conn != MTU {
		if send_notification {
			(&mut*conn).close();
		} else {
			let b = Box::from_raw(conn);
			drop(b);
			set_conn(this, MTU);
		}

		let plugins_len = *((this+0x790) as *const u32);
		let array_start = *((this+0x78c) as *const u32);
		let mut i = 0;
		while i < plugins_len {
			let plugin = *((array_start+4*i) as *const usize);
			let x = *(plugin as *const u32);
			let on_close_connection_func = *((x+0x1c) as *const extern "thiscall" fn(usize, usize, u32, u16));
			on_close_connection_func(plugin, this, ip, port);
			i += 1;
		}
	}
}

extern "thiscall" fn new_connect(this: usize, host: *const c_char, port: u16, password: *const c_char, password_len: u32, socket_index: u32) -> bool {
	match connect(this, host, port, password, password_len, socket_index) {
		Ok(()) => true,
		Err(e) => {
			dbg!(e);
			false
		}
	}
}

fn connect(this: usize, host: *const c_char, port: u16, _password: *const c_char, _password_len: u32, _socket_index: u32) -> Res<()> {
	let conn = get_conn(this);
	if conn != MTU {
		let b = unsafe { Box::from_raw(conn) };
		drop(b);
		set_conn(this, MTU);
	}
	let host = unsafe { CStr::from_ptr(host).to_str().unwrap() };
	let port = if port == 1001 { 21836 } else { port };
	let mut conn = Box::new(Connection::new(host, port)?);
	conn.send(b"\x043.25 ND1", REL_ORD)?;
	set_conn(this, Box::into_raw(conn));
	Ok(())
}

unsafe extern "thiscall" fn new_deallocate_packet(_this: usize, packet: *const RakPacket) {
	if packet.is_null() {
		return;
	}

	let b = Box::from_raw(packet as *mut RakPacket);
	let d = Box::from_raw(b.data);
	drop(d);
	drop(b);
}

unsafe extern "thiscall" fn new_get_average_ping(this: usize, _ip: u32, _port: u16) -> u32 {
	let conn = &*get_conn(this);
	conn.average_ping()
}

unsafe extern "thiscall" fn new_get_last_ping(this: usize, _ip: u32, _port: u16) -> u32 {
	let conn = &*get_conn(this);
	conn.last_ping()
}

unsafe extern "thiscall" fn new_receive(this: usize) -> *const RakPacket {
	let conn = get_conn(this);
	if conn == MTU {
		return ptr::null();
	}
	let conn = &mut*conn;
	match conn.receive() {
		Ok(packet) => {
			if !packet.is_null() {
				let plugins_len = *((this+0x790) as *const u32);
				let array_start = *((this+0x78c) as *const u32);
				let mut i = 0;
				while i < plugins_len {
					let plugin = *((array_start+4*i) as *const usize);
					let x = *(plugin as *const u32);
					let on_receive_func = *((x+0x14) as *const extern "thiscall" fn(usize, usize, *const RakPacket) -> u32);
					let retval = on_receive_func(plugin, this, packet);
					if retval == STOP_PROCESSING_AND_DEALLOCATE {
						new_deallocate_packet(this, packet);
						return ptr::null();
					} else if retval == STOP_PROCESSING {
						return ptr::null();
					}
					i += 1;
				}
			}
			packet
		},
		_ => ptr::null(),
	}
}

unsafe extern "thiscall" fn new_send(this: usize, data: *const c_uchar, len: u32, _priority: u32, reliability: u32, _ordering_channel: u8, _ip: u32, _port: u16, _broadcast: bool) -> bool {
	let conn = get_conn(this);
	if conn == MTU {
		return false;
	}
	let conn = &mut*conn;
	match conn.send(std::slice::from_raw_parts(data, len as usize), reliability) {
		Ok(()) => true,
		Err(e) => {dbg!(e); false }
	}
}

extern "thiscall" fn new_shutdown(_this: usize, _block_dur: u32, _channel: u8) {
}

unsafe extern "thiscall" fn new_startup(_this: usize) -> bool {
	true
}

pub fn patch_raknet() {
	detour(RAK_CLOSE_CONNECTION, new_close_connection as LPVOID);
	detour(RAK_CONNECT, new_connect as LPVOID);
	detour(RAK_DEALLOCATE_PACKET, new_deallocate_packet as LPVOID);
	detour(RAK_GET_AVERAGE_PING, new_get_average_ping as LPVOID);
	detour(RAK_GET_LAST_PING, new_get_last_ping as LPVOID);
	detour(RAK_RECEIVE, new_receive as LPVOID);
	detour(RAK_SEND, new_send as LPVOID);
	detour(RAK_SHUTDOWN, new_shutdown as LPVOID);
	detour(RAK_STARTUP, new_startup as LPVOID);
	patch_byte(CLOSE_CONNECT_PARAM, 0);
}
