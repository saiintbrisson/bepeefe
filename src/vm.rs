use std::{alloc::Layout, ops::Deref, sync::Arc};

use mem::{Memory, Region};

use crate::{
    isa::{self, Insn, load::BPF_PSEUDO_MAP_FD},
    maps::{BpfMap, MapPinning, MapRepr},
    object::{Context, EbpfProgram, Val},
};

pub mod debugger;
pub mod mem;

const DEFAULT_SIZE: usize = 1024 * 1024 * 2; // 2 MiB

pub struct PreparedProgram(Arc<EbpfProgram>);
impl Deref for PreparedProgram {
    type Target = EbpfProgram;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

pub struct Vm {
    maps: Vec<BpfMap>,

    pub code: VmCode,
    pub exit: bool,

    pub registers: [u64; 11],
    call_stack: Vec<StackFrame>,

    pub mem: Memory,
    stack: Region,
}

#[derive(Clone, Copy, Debug, Default)]
pub enum MapReuseStrategy {
    /// Maps with no pinning instruction will not be reused,
    /// a new map and FD will be generated instead for each
    /// program that declares maps.
    #[default]
    None,
    /// Maps with no pinning instrucion will be matched to
    /// existing maps with the same name, previously loaded
    /// by other programs.
    MatchByName,
}

impl Vm {
    /// Instantiates a new virtual machine with the given
    /// program loaded. A 2MiB memory region is allocated
    /// and zeroed. Maps are loaded and initiated. Code
    /// is loaded to the memory and PC is set to `entry`.
    pub fn new() -> Self {
        let mut mem = Memory::with_capacity(DEFAULT_SIZE);

        let stack_layout = Layout::from_size_align(STACK_FUNCTION_SIZE * 8, 8).unwrap();
        let stack = mem.alloc_layout(stack_layout).expect("stack is valid");

        let mut registers: [u64; 11] = Default::default();
        registers[10] = (stack.end() - 1) as u64;

        Self {
            maps: Default::default(),
            code: Default::default(),
            exit: false,
            registers,
            call_stack: Vec::with_capacity(8),
            mem,
            stack,
        }
    }

    /// Prepares an eBPF program to be executed by the Vm, creating and linking all maps.
    ///
    /// `map_reuse` dictates how the Vm will find existing maps and reuse them
    /// if `pinning` is not declared for the map.
    pub fn prepare(
        &mut self,
        mut prog: EbpfProgram,
        map_reuse: MapReuseStrategy,
    ) -> PreparedProgram {
        self.maps.reserve(prog.maps.len());

        let mut maps_fds = Vec::with_capacity(prog.maps.len());
        for spec in &prog.maps {
            let btf = prog.btf.clone().unwrap();

            let by_name = self.maps.iter().find(|map| map.spec.name == spec.name);
            match (map_reuse, spec.pinning, by_name) {
                (MapReuseStrategy::MatchByName, _, Some(map))
                | (_, MapPinning::ByName, Some(map)) => {
                    maps_fds.push((spec, map.fd));
                    continue;
                }
                (_, _, Some(_)) => todo!("map with name '{}' already exists", spec.name),
                _ => {}
            }

            let bpf_map = BpfMap {
                fd: self.maps.len() as i32,
                repr: MapRepr::create_from_btf(&mut self.mem, &btf, &spec)
                    .expect("invalid map type"),
                spec: spec.clone(),
                btf,
            };

            maps_fds.push((spec, bpf_map.fd));
            self.maps.push(bpf_map);
        }

        // Relocate map calls with their initialized FDs
        for (insn_offset, (sec, sec_offset)) in &prog.map_relos {
            let map = maps_fds
                .iter()
                .find(|(spec, _)| spec.sec_idx == sec.0 && spec.sec_offset == *sec_offset as u32);

            if let Some((_, fd)) = map {
                let insn = &mut prog.insns[*insn_offset];

                insn.with_src_reg(BPF_PSEUDO_MAP_FD);
                insn.with_imm(*fd);
            }
        }

        let prog = Arc::new(prog);

        crate::verifier::VerifierState::new(&self, prog.clone()).run();

        PreparedProgram(prog)
    }

    pub fn run(&mut self, prog: &PreparedProgram, ctx: &[Context]) {
        self.registers = Default::default();
        self.registers[10] = (self.stack.end() - 1) as u64;

        self.exit = false;
        self.code.insns = prog.0.insns.clone();
        self.code.set_pc(0);

        // for (idx, insn) in self.code.insns.iter().enumerate() {
        //     eprintln!(
        //         "{idx}: {}: {}",
        //         crate::isa::INSTRUCTION_NAME_TABLE[insn.opcode() as usize],
        //         crate::vm::debugger::disasm(*insn, self.code.insns.get(idx + 1).cloned())
        //     );
        // }

        let ctx_regions: Vec<_> = ctx
            .iter()
            .enumerate()
            .filter_map(|(idx, ctx)| match ctx {
                Context::Buffer(buf) => {
                    let ctx_reg = self.mem.push_bytes(&buf, None);
                    self.registers[idx + 1] = ctx_reg.start() as u64;
                    Some(ctx_reg)
                }
                &Context::Value(val) => {
                    self.registers[idx + 1] = val;
                    None
                }
            })
            .collect();

        while !self.exit {
            let Some(insn) = self.code.step() else {
                panic!();
            };

            // eprintln!("{}: {}", self.code.pc - 1, debugger::debugger(&self, insn));

            isa::INSTRUCTION_TABLE[insn.opcode() as usize](self, insn);
        }

        for ctx_reg in ctx_regions.into_iter().rev() {
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

    pub fn map_by_fd(&self, fd: i32) -> Option<&BpfMap> {
        self.maps.get(fd as usize)
    }
    pub fn map_by_id_mut(&mut self, id: usize) -> Option<&mut BpfMap> {
        self.maps.get_mut(id)
    }

    pub fn map_by_name(&mut self, name: &str) -> Option<&mut BpfMap> {
        self.maps.iter_mut().find(|map| map.spec.name == name)
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

    pub fn map(&mut self, name: &str) -> MapHandle<'_> {
        let map = self
            .maps
            .iter_mut()
            .find(|map| map.spec.name == name)
            .unwrap();

        MapHandle {
            mem: &mut self.mem,
            map,
        }
    }
}

pub struct MapHandle<'a> {
    mem: &'a mut Memory,
    map: &'a mut BpfMap,
}

impl<'a> MapHandle<'a> {
    pub fn update(&mut self, key: &Val, val: &Val) -> std::io::Result<()> {
        let key_ty = self
            .map
            .btf
            .get_type(self.map.spec.key.clone().unwrap())
            .unwrap();
        let val_ty = self
            .map
            .btf
            .get_type(self.map.spec.value.clone().unwrap())
            .unwrap();

        let key = key.to_bytes(&self.map.btf, key_ty);
        let val = val.to_bytes(&self.map.btf, val_ty);

        self.map.repr.update(&mut self.mem, &key, &val)
    }
}

#[derive(Default)]
pub struct VmCode {
    insns: Vec<Insn>,
    pc: usize,
}

impl VmCode {
    pub fn step(&mut self) -> Option<Insn> {
        self.pc += 1;
        self.insns.get(self.pc - 1).copied()
    }

    pub fn peek(&self) -> Option<Insn> {
        self.insns.get(self.pc).copied()
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

#[derive(Default, Debug)]
struct StackFrame {
    ret_addr: usize,
    registers: [u64; 4],
}
