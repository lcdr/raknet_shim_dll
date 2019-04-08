#![feature(abi_thiscall)]
mod detour;
mod raknet;
mod tcpudp;
mod tls;

use raknet::patch_raknet;

static mut BASE: usize = 0;

use winapi::{
	shared::minwindef::{BOOL, DWORD, HINSTANCE, LPVOID, TRUE},
	um::libloaderapi::GetModuleHandleA
};

#[no_mangle]
#[allow(unused_variables)]
pub extern "system" fn DllMain(
	dll_module: HINSTANCE,
	call_reason: DWORD,
	reserved: LPVOID)
	-> BOOL {
	const DLL_PROCESS_ATTACH: DWORD = 1;

	match call_reason {
		DLL_PROCESS_ATTACH => init(),
		_ => TRUE
	}
}

fn init() -> BOOL {
	unsafe { BASE = GetModuleHandleA(std::ptr::null()) as usize; }
	patch_raknet();
	TRUE
}
