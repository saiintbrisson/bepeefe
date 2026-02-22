use std::{
    ops::Deref,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU32, Ordering},
    },
};

use crate::{
    isa::{
        self,
        load::{BPF_PSEUDO_MAP_FD, BPF_PSEUDO_MAP_VALUE},
    },
    maps::{BpfMap, MapPinning, MapRepr},
    object::{Context, EbpfProgram},
    value::ProgramValue,
    verifier::Verifier,
    vm::state::PtrTag,
};

pub mod debugger;
mod state;

#[doc(hidden)]
pub use state::State;

pub struct Vm {
    maps: RwLock<Vec<Arc<BpfMap>>>,
    rng_state: AtomicU32,
}

impl Vm {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            maps: Default::default(),
            rng_state: AtomicU32::new(0xDEAD_BEEF),
        })
    }

    pub(crate) fn find_map(&self, fd: u16) -> Option<Arc<BpfMap>> {
        let maps = self.maps.read().unwrap();
        maps.get(fd as usize).cloned()
    }

    pub fn set_rng_seed(&self, seed: u32) {
        self.rng_state.store(seed, Ordering::Release);
    }

    /// Returns a random u32 and updates the RNG
    /// state applying a xorshift.
    pub(crate) fn prandom_u32(&self) -> u32 {
        let mut rand = 0;
        let _ = self
            .rng_state
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |mut s| {
                s ^= s << 13;
                s ^= s >> 17;
                s ^= s << 5;
                rand = s;
                Some(s)
            });
        rand
    }
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
    /// Prepares an eBPF program to be executed by the Vm, creating and linking all maps.
    ///
    /// `map_reuse` dictates how the Vm will find existing maps and reuse them
    /// if `pinning` is not declared for the map.
    pub fn prepare(
        self: &Arc<Vm>,
        mut prog: EbpfProgram,
        map_reuse: MapReuseStrategy,
    ) -> PreparedProgram {
        let mut maps = self.maps.write().unwrap();
        maps.reserve(prog.maps.len());

        let mut maps_fds = Vec::with_capacity(prog.maps.len());
        for spec in &prog.maps {
            let btf = prog.btf.clone().unwrap();

            let by_name = maps.iter().find(|map| map.spec.name == spec.name);
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
                fd: maps.len() as i32,
                repr: MapRepr::create_from_btf(&btf, spec).expect("invalid map type"),
                spec: spec.clone(),
                btf,
            };

            maps_fds.push((spec, bpf_map.fd));
            maps.push(Arc::new(bpf_map));
        }

        // Fill initial data for data-section maps (.rodata, .data, etc.)
        for map in maps.iter_mut() {
            if let Some(data) = &map.spec.initial_data {
                let key = 0u32.to_ne_bytes();
                map.repr
                    .update(&key, &data)
                    .expect("failed to fill initial data");
            }
        }
        drop(maps);

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

        // Resolve data relocations (.rodata, .data, .bss) by encoding
        // BPF_PSEUDO_MAP_VALUE: imm = map fd, next_imm = offset within value
        for (insn_offset, (sec, offset_in_sec)) in &prog.data_relos {
            let (_, fd) = maps_fds
                .iter()
                .find(|(spec, _)| spec.sec_idx == sec.0)
                .expect("data relo targets unknown section");

            prog.insns[*insn_offset].with_src_reg(BPF_PSEUDO_MAP_VALUE);
            prog.insns[*insn_offset].with_imm(*fd);
            prog.insns[*insn_offset + 1].with_imm(*offset_in_sec as i32);
        }

        let prog = Arc::new(prog);
        let verifier = Verifier::new(self, prog.clone()).unwrap();
        if let Err(err) = verifier.run() {
            match &err {
                crate::verifier::VerifierError::Other {
                    insn,
                    insn_off,
                    msg,
                    registers,
                } => {
                    let btf = prog.btf.as_ref();
                    let radius = 3;
                    let start = insn_off.saturating_sub(radius);
                    let end = (insn_off + radius + 1).min(prog.insns.len());

                    eprintln!();
                    let mut prev_line_off: Option<u32> = None;
                    for pc in start..end {
                        let cur = prog.insns[pc];
                        let next = prog.insns.get(pc + 1).copied();
                        let dis = crate::vm::debugger::disasm(cur, next);

                        let line_entry = btf.and_then(|b| {
                            let entry = prog.line_info.get(&pc)?;
                            let line = b.string(entry.line_off)?;
                            Some((entry.line_off, entry.line_no, line.into_owned()))
                        });

                        let src_line = match &line_entry {
                            Some((off, _, _)) if prev_line_off == Some(*off) => String::new(),
                            Some((_, line_no, line)) => {
                                format!("        // @ {line_no}: {}", line.trim())
                            }
                            None => String::new(),
                        };

                        if let Some((off, _, _)) = &line_entry {
                            prev_line_off = Some(*off);
                        }

                        if pc == *insn_off {
                            eprintln!("  > {pc:>3}: {dis}{src_line}");
                            eprintln!("         ^ {msg}");

                            let dst = insn.dst_reg();
                            let src = insn.src_reg();
                            eprintln!(
                                "         r{dst} = {:?}{}",
                                registers[dst as usize],
                                if src != dst {
                                    format!(", r{src} = {:?}", registers[src as usize])
                                } else {
                                    String::new()
                                }
                            );
                        } else {
                            eprintln!("    {pc:>3}: {dis}{src_line}");
                        }
                    }
                    eprintln!();
                }
                err => eprintln!("{err}"),
            }

            panic!("verification failed: {err}")
        };

        PreparedProgram::new(self.clone(), prog)
    }

    pub fn map(&self, name: &str) -> MapHandle {
        let maps = self.maps.read().unwrap();
        MapHandle(
            maps.iter()
                .find(|map| map.spec.name == name)
                .unwrap()
                .clone(),
        )
    }
}

const STACK_SIZE: usize = 512;
const SLOTS: usize = 64;

#[derive(Clone)]
pub struct PreparedProgram {
    pub(crate) vm: Arc<Vm>,
    prog: Arc<EbpfProgram>,
    buf_pool: Arc<RwLock<Vec<Vec<u8>>>>,
    param_sizes: Vec<u32>,
}

impl PreparedProgram {
    pub fn new(vm: Arc<Vm>, prog: Arc<EbpfProgram>) -> Self {
        let btf = prog.btf.as_ref().unwrap();
        let param_sizes: Vec<_> = prog
            .sig
            .params_types
            .iter()
            .map(|(_, param)| btf.get_type(*param).unwrap().kind.size(btf).unwrap())
            .collect();
        let ctx_size = param_sizes.iter().sum::<u32>().next_power_of_two();

        let mut buf_pool = Vec::with_capacity(SLOTS);
        for _ in 0..SLOTS {
            buf_pool.push(vec![0; ctx_size as usize + STACK_SIZE]);
        }

        Self {
            vm,
            prog,
            buf_pool: Arc::new(RwLock::new(buf_pool)),
            param_sizes,
        }
    }

    pub fn run(&self, ctx: &[Context]) -> u64 {
        let buf = self
            .buf_pool
            .write()
            .unwrap()
            .pop()
            .expect("no available execution slots");

        let mut state = State {
            prog: self.clone(),
            buf,
            pc: 0,
            registers: Default::default(),
            exit: false,
        };
        state.registers[10] = PtrTag::Local as u64 | state.buf.len() as u64 - 1;

        assert_eq!(ctx.len(), self.param_sizes.len(), "TODO");

        let mut buf_idx = 0;

        for ((idx, ctx), param_size) in ctx.iter().enumerate().zip(&self.param_sizes) {
            match ctx {
                Context::Buffer(buf) => {
                    assert_eq!(*param_size as usize, buf.len());

                    state.buf[buf_idx..buf_idx + buf.len()].copy_from_slice(&buf);
                    state.registers[idx + 1] = PtrTag::Local as u64 | buf_idx as u64;

                    buf_idx += buf.len();
                }
                &Context::Value(val) => {
                    assert_eq!(val >> (param_size * 8), 0);

                    state.registers[idx + 1] = val;
                }
            }
        }

        while !state.exit {
            let Some(insn) = self.prog.insns.get(state.pc) else {
                panic!();
            };
            state.pc += 1;

            isa::INSTRUCTION_TABLE[insn.opcode() as usize](&mut state, *insn);
        }

        state.registers[0]
    }
}

impl Deref for PreparedProgram {
    type Target = EbpfProgram;

    fn deref(&self) -> &Self::Target {
        self.prog.as_ref()
    }
}

pub struct MapHandle(Arc<BpfMap>);

impl MapHandle {
    pub fn update(
        &self,
        key: &(impl serde::Serialize + ?Sized),
        val: &(impl serde::Serialize + ?Sized),
    ) -> std::io::Result<()> {
        let key = crate::value::to_value(key).unwrap();
        let val = crate::value::to_value(val).unwrap();

        let key_ty = self.0.btf.get_type(self.0.spec.key.unwrap()).unwrap();
        let val_ty = self.0.btf.get_type(self.0.spec.value.unwrap()).unwrap();

        let key = key.to_bytes(&self.0.btf, key_ty);
        let val = val.to_bytes(&self.0.btf, val_ty);

        self.0.repr.update(&key, &val)
    }

    pub fn push(&mut self, val: &(impl serde::Serialize + ?Sized)) -> std::io::Result<()> {
        let val = crate::value::to_value(val).unwrap();
        let val_ty = self.0.btf.get_type(self.0.spec.value.unwrap()).unwrap();

        let val = val.to_bytes(&self.0.btf, val_ty);
        self.0.repr.push(&val)
    }

    pub fn pop<T: for<'de> serde::Deserialize<'de>>(&mut self) -> Option<T> {
        let val_ty = self.0.btf.get_type(self.0.spec.value.unwrap()).unwrap();

        let addr = self.0.repr.pop()?;
        let bytes = self.0.repr.read_bytes(addr, self.0.repr.value_size())?;
        let pv = ProgramValue::from_bytes(&self.0.btf, val_ty, &bytes);
        Some(crate::value::from_value(pv).unwrap())
    }

    pub fn lookup<T: for<'de> serde::Deserialize<'de>>(
        &self,
        key: &(impl serde::Serialize + ?Sized),
    ) -> Option<T> {
        let key = crate::value::to_value(key).unwrap();
        let key_ty = self.0.btf.get_type(self.0.spec.key.unwrap()).unwrap();
        let val_ty = self.0.btf.get_type(self.0.spec.value.unwrap()).unwrap();

        let key = key.to_bytes(&self.0.btf, key_ty);
        let addr = self.0.repr.lookup(&key)?;
        let bytes = self.0.repr.read_bytes(addr, self.0.repr.value_size())?;
        let pv = ProgramValue::from_bytes(&self.0.btf, val_ty, &bytes);
        Some(crate::value::from_value(pv).unwrap())
    }

    pub fn clear(&mut self) {
        self.0.repr.clear();
    }

    pub fn btf(&self) -> &crate::btf::Btf {
        &self.0.btf
    }

    pub fn btf_val_type(&self) -> &crate::btf::BtfType {
        self.0
            .btf
            .get_type(self.0.spec.value.unwrap())
            .expect("map missing value BTF type")
    }
}
