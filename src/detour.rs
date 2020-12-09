use winapi::shared::minwindef::{BYTE, DWORD, LPVOID};
use winapi::um::memoryapi::VirtualProtect;
use winapi::um::winnt::PAGE_EXECUTE_READWRITE;

use crate::BASE;

const JMP_OPCODE: u8 = 0xE9;

pub fn detour(old: usize, new: LPVOID) {
	unsafe {
		let old = (old + BASE) as LPVOID;
		let jmp_distance: DWORD = new as DWORD - old as DWORD - 5;
		let mut old_protect: DWORD = PAGE_EXECUTE_READWRITE;
		VirtualProtect(old, 5, PAGE_EXECUTE_READWRITE, &mut old_protect);
		*(old as *mut BYTE) = JMP_OPCODE;
		*(((old as usize)+1) as *mut DWORD) = jmp_distance;
		VirtualProtect(old, 5, old_protect, &mut old_protect);
	}
}

pub fn patch_byte(dst: usize, new: BYTE) {
	unsafe {
		let dst = (dst + BASE) as LPVOID;
		let mut old_protect: DWORD = PAGE_EXECUTE_READWRITE;
		VirtualProtect(dst, 1, PAGE_EXECUTE_READWRITE, &mut old_protect);
		*(dst as *mut BYTE) = new;
		VirtualProtect(dst, 1, old_protect, &mut old_protect);
	}
}
