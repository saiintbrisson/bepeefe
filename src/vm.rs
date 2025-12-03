use std::alloc::Layout;

use mem::{Memory, Region};

use crate::{
    isa::{self, Insn},
    loader::{Context, Entrypoint, Program},
    maps::BpfMap,
};

mod debugger;
pub mod mem;

const DEFAULT_SIZE: usize = 1024 * 1024 * 2; // 2 MiB

pub struct Vm {
    maps: Vec<BpfMap>,

    pub code: VmCode,
    pub exit: bool,

    pub registers: [u64; 11],
    call_stack: Vec<StackFrame>,

    pub mem: Memory,
    stack: Region,
}

impl Vm {
    /// Instantiates a new virtual machine with the given
    /// program loaded. A 2MiB memory region is allocated
    /// and zeroed. Maps are loaded and initiated. Code
    /// is loaded to the memory and PC is set to `entry`.
    pub fn new(mut program: Program) -> Self {
        let mut mem = Memory::with_capacity(DEFAULT_SIZE);

        let code = VmCode::new(program.code);
        let stack_layout = Layout::from_size_align(100 * 1024, 8).unwrap();
        let stack = mem.alloc_layout(stack_layout).expect("stack is valid");

        for map in &mut program.maps {
            map.repr.init(&mut mem);
        }

        let mut registers: [u64; 11] = Default::default();
        registers[10] = (stack.end() - 1) as u64;

        Self {
            maps: program.maps,
            code,
            exit: false,
            registers,
            call_stack: Vec::with_capacity(8),
            mem,
            stack,
        }
    }

    pub fn run(&mut self, entrypoint: Entrypoint) {
        self.registers = Default::default();
        self.registers[10] = (self.stack.end() - 1) as u64;

        self.exit = false;
        self.code.set_pc(entrypoint.offset);

        let ctx_reg = if let Some(ctx) = entrypoint.ctx {
            match ctx {
                Context::Buffer(buf) => {
                    let ctx_reg = self.mem.push_bytes(&buf, None);
                    self.registers[1] = ctx_reg.start() as u64;

                    Some(ctx_reg)
                }
                Context::Value(val) => {
                    self.registers[1] = val;
                    None
                }
            }
        } else {
            None
        };

        while !self.exit {
            let Some(insn) = self.code.step() else {
                panic!();
            };

            isa::INSTRUCTION_TABLE[insn.opcode() as usize](self, insn);
        }

        if let Some(ctx_reg) = ctx_reg {
            self.mem.reclaim_region(ctx_reg);
        }
    }

    pub fn call(&mut self, offset: i32) {
        assert!(
            self.call_stack.len() < 8,
            "no more than 8 nested calls allowed"
        );

        self.call_stack.push(StackFrame {
            ret_addr: self.code.pc,
            registers: self.registers[6..=9].try_into().unwrap(),
        });

        self.registers[10] -= STACK_FUNCTION_SIZE as u64;
        self.code.add_offset(offset as isize);
    }

    pub fn call_exit(&mut self) {
        let Some(frame) = self.call_stack.pop() else {
            self.exit = true;
            return;
        };

        self.code.pc = frame.ret_addr;
        self.registers[10] += STACK_FUNCTION_SIZE as u64;

        // Registers R6-R9 are restored while R1-R5 are reset to unreadable.
        // https://github.com/torvalds/linux/blob/master/Documentation/bpf/classic_vs_extended.rst
        self.registers[1..=5].fill(0);
        self.registers[6..=9].copy_from_slice(&frame.registers);
    }
}

impl Vm {
    pub fn map_by_fd_exists(&self, fd: i32) -> bool {
        (fd as usize) < self.maps.len()
    }

    pub fn map_by_id(&mut self, id: usize) -> Option<&mut BpfMap> {
        self.maps.get_mut(id)
    }

    pub fn map_by_name(&mut self, name: &str) -> Option<&mut BpfMap> {
        self.maps.iter_mut().find(|map| map.name == name)
    }

    pub(crate) fn map_lookup_from_guest(&self, map: usize, key_addr: usize) -> Option<usize> {
        let map = &self.maps[map as usize];
        let key = self
            .mem
            .slice(key_addr, map.repr.key_size())
            .expect("tried reading out of memory bounds");
        map.repr.lookup(&self.mem, key)
    }

    pub(crate) fn map_update_from_guest(
        &mut self,
        map_idx: usize,
        key_addr: usize,
        value_addr: usize,
    ) -> std::io::Result<()> {
        let map = self
            .maps
            .get_mut(map_idx)
            .ok_or(std::io::ErrorKind::NotFound)?;
        map.repr
            .update_from_guest(&mut self.mem, key_addr, value_addr)
    }
}

pub struct VmCode {
    code: Vec<Insn>,
    pc: usize,
}

impl VmCode {
    pub fn new(code: Vec<u8>) -> Self {
        assert!(code.len().is_multiple_of(8));

        Self {
            code: unsafe { std::mem::transmute(code) },
            pc: 0,
        }
    }

    pub fn step(&mut self) -> Option<Insn> {
        self.pc += 1;
        self.code.get(self.pc - 1).copied()
    }

    pub fn peek(&self) -> Option<Insn> {
        self.code.get(self.pc).copied()
    }

    pub fn add_offset(&mut self, offset: isize) {
        self.pc = (self.pc as isize + offset) as usize;
    }

    pub fn set_pc(&mut self, pc: usize) {
        self.pc = pc;
    }

    pub fn pc(&self) -> usize {
        self.pc
    }
}

/// This is a arbitrary number. The eBPF verifier is able to figure out stack
/// usage per function by tracking register states and using a PTR_TO_STACK
/// state. I won't do this, for now at least.
const STACK_FUNCTION_SIZE: usize = 512;

#[derive(Debug)]
struct StackFrame {
    ret_addr: usize,
    registers: [u64; 4],
}
