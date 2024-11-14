use std::alloc::Layout;

use mem::{GuestAddr, VmMem, VmMemRegion};

use crate::program::Program;

pub mod mem;

const DEFAULT_SIZE: usize = 1024 * 1024; // 1 MiB

pub struct Vm {
    pub program: Program,
    pub program_counter: i32,
    pub exit: bool,

    pub registers: [u64; 11],

    pub mem: VmMem,
    #[allow(dead_code)]
    stack: VmMemRegion,
}

impl Vm {
    pub fn new(mut program: Program) -> Self {
        let mut mem = VmMem::new(DEFAULT_SIZE);

        let stack = mem
            .alloc_layout(
                Layout::new::<u8>()
                    .repeat_packed(10 * 1024)
                    .expect("valid stack layout"),
            )
            .expect("stack is valid");

        for map in &mut program.maps {
            map.inner.init(&mut mem);
        }

        let mut registers: [u64; 11] = Default::default();
        registers[10] = stack.guest_end_addr().0 as u64 - 1;

        Self {
            stack,
            program_counter: program.entry as i32,
            program,
            exit: false,
            registers,
            mem,
        }
    }

    pub fn call(&mut self, offset: i32) {
        let mut frame = StackFrame {
            ret_addr: Some(self.program_counter),
            registers: Default::default(),
            base_ptr: self.registers[10],
        };

        frame.registers.copy_from_slice(&self.registers[6..=9]);

        self.registers[10] -= STACK_FUNCTION_SIZE as u64;

        self.mem
            .copy_from(
                GuestAddr(self.registers[10] as usize),
                &raw const frame as *const u8,
                STACK_FRAME_SIZE,
            )
            .unwrap();

        self.registers[10] -= STACK_FRAME_SIZE as u64;
        self.program_counter = self.program_counter + offset;
    }

    pub fn pop_stack_frame(&mut self) {
        let stack_ptr = self.registers[10];
        if stack_ptr >= self.stack.guest_end_addr().0 as u64 {
            self.exit = true;
            return;
        }

        let frame: StackFrame = self
            .mem
            .read_as(GuestAddr(stack_ptr as usize + STACK_FRAME_SIZE))
            .unwrap();

        if let Some(addr) = frame.ret_addr {
            self.program_counter = addr;
        } else {
            self.exit = true;
        }

        self.registers[10] = frame.base_ptr;

        // Registers R6-R9 are restored while R1-R5 are reset to unreadable.
        // https://github.com/torvalds/linux/blob/master/Documentation/bpf/classic_vs_extended.rst
        (&mut self.registers[1..=5]).copy_from_slice(&[0; 5]);
        (&mut self.registers[6..=9]).copy_from_slice(&frame.registers);
    }

    pub fn map_lookup_elem(&self, map: usize, key_addr: GuestAddr) -> GuestAddr {
        let map = &self.program.maps[map as usize];
        let key = self
            .mem
            .read(key_addr, map.inner.key_size())
            .expect("tried reading of memory bounds");
        map.inner
            .lookup_elem(key)
            .and_then(|key| self.mem.into_guest_addr(key))
            .unwrap_or_default()
    }
}

/// This is a arbitrary number. The eBPF verifier is able to figure out stack
/// usage per function by tracking register states and using a PTR_TO_STACK
/// state. I won't do this, for now at least.
const STACK_FUNCTION_SIZE: usize = 512;
const STACK_FRAME_SIZE: usize = size_of::<StackFrame>();

#[repr(C)]
#[derive(Debug)]
pub struct StackFrame {
    /// Return address of the caller.
    pub ret_addr: Option<i32>,
    /// Registers preserved between calls, R6 to R9.
    pub registers: [u64; 4],
    /// The base stack pointer of this frame.
    pub base_ptr: u64,
}
