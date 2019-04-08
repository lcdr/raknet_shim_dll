use winapi::shared::minwindef::{BYTE, DWORD, LPVOID};
use winapi::um::memoryapi::VirtualProtect;
use winapi::um::winnt::PAGE_EXECUTE_READWRITE;

use crate::BASE;

const NOP_OPCODE: u8 = 0x90;
const JMP_OPCODE: u8 = 0xE9;

static mut OLD_PROTECT: DWORD = PAGE_EXECUTE_READWRITE;

pub fn detour(old: usize, new: LPVOID) {
	unsafe {
		let old = (old + BASE) as LPVOID;
		let jmp_distance: DWORD = new as DWORD - old as DWORD - 5;
		VirtualProtect(old, 5, PAGE_EXECUTE_READWRITE, &mut OLD_PROTECT);
		*(old as *mut BYTE) = JMP_OPCODE;
		*(((old as usize)+1) as *mut DWORD) = jmp_distance;
		VirtualProtect(old, 5, OLD_PROTECT, &mut OLD_PROTECT);
	}
}

pub fn nop(at: usize, count: u8) {
	unsafe {
		let at = (at + BASE) as LPVOID;
		VirtualProtect(at, 5, PAGE_EXECUTE_READWRITE, &mut OLD_PROTECT);
		let mut i = 0;
		while i < count {
			*((at as usize+i as usize) as *mut BYTE) = NOP_OPCODE;
			i += 1;
		}
		VirtualProtect(at, 5, OLD_PROTECT, &mut OLD_PROTECT);
	}
}