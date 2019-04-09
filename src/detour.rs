use winapi::shared::minwindef::{BYTE, DWORD, LPVOID};
use winapi::um::memoryapi::VirtualProtect;
use winapi::um::winnt::PAGE_EXECUTE_READWRITE;

use crate::BASE;

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
