use std::sync::Arc;

use super::{MapReuseStrategy, PreparedProgram, Vm};
use crate::{
    error::PrepareError,
    isa::load::{BPF_PSEUDO_MAP_FD, BPF_PSEUDO_MAP_VALUE},
    maps::{BpfMap, MapPinning, MapRepr},
    object::{Deferred, EbpfProgram},
    verifier::{Verifier, VerifierConfig},
};

impl Vm {
    /// Hooks an [`EbpfProgram`] into the Vm so it can be run. We do three main
    /// things: maps are created (or reused from earlier loads), `ld_imm64`
    /// relocations are patched with the resulting FDs, and the verifier walks
    /// every reachable instruction.
    ///
    /// Maps are created fresh by default. `map_reuse` and the map's own
    /// `pinning` attribute can change that. A map declaring `pinning =
    /// LIBBPF_PIN_BY_NAME` will attach to an existing map with the same name in
    /// the Vm, and [`MapReuseStrategy::MatchByName`] extends that behavior to
    /// every map regardless of its pinning. Without those opt-ins, name
    /// collisions across programs are rejected as
    /// [`PrepareError::DuplicateMap`].
    ///
    /// Data-section maps (`.rodata`/`.data`/`.bss`) are special. They're always
    /// private per program, each gets its own copy populated from the section's
    /// initial bytes, and their names are disambiguated internally so two
    /// programs can each have their own `.rodata` without colliding.
    pub fn prepare(
        self: &Arc<Vm>,
        prog: EbpfProgram,
        map_reuse: MapReuseStrategy,
        verifier_config: &VerifierConfig,
    ) -> Result<Arc<PreparedProgram>, PrepareError> {
        let original_len = self.maps.lock().unwrap().len();
        match self.prepare_inner(prog, map_reuse, verifier_config) {
            Ok(p) => Ok(p),
            Err(e) => {
                self.maps.lock().unwrap().truncate(original_len);
                Err(e)
            }
        }
    }

    fn prepare_inner(
        self: &Arc<Vm>,
        mut prog: EbpfProgram,
        map_reuse: MapReuseStrategy,
        verifier_config: &VerifierConfig,
    ) -> Result<Arc<PreparedProgram>, PrepareError> {
        let mut maps = self.maps.lock().unwrap();
        maps.reserve(prog.maps.len());

        let mut maps_fds = Vec::with_capacity(prog.maps.len());
        for spec in &prog.maps {
            let btf = prog.btf.clone();

            // Data-section maps (.rodata/.data/.bss) are private to each program load, so
            // they don't participate in by-name reuse or duplicate-name checks against maps
            // from other programs.
            let is_data_section = spec.initial_data.is_some();

            if !is_data_section {
                let by_name = maps.iter().find(|map| map.spec.name == spec.name);
                match (map_reuse, spec.pinning, by_name) {
                    (MapReuseStrategy::MatchByName, _, Some(map))
                    | (_, MapPinning::ByName, Some(map)) => {
                        maps_fds.push((spec, map.fd));
                        continue;
                    }
                    (_, _, Some(_)) => {
                        return Err(PrepareError::DuplicateMap {
                            name: spec.name.clone(),
                        });
                    }
                    _ => {}
                }
            }

            let repr = MapRepr::create_from_btf(&btf, spec)?;

            let fd = maps.len() as i32;
            let mut stored_spec = spec.clone();
            if is_data_section {
                // Disambiguate so two programs can each have their own data sections.
                stored_spec.name = format!("{}#{fd}", stored_spec.name);
            }

            let bpf_map = BpfMap {
                fd,
                repr,
                spec: stored_spec,
                btf,
            };

            maps_fds.push((spec, fd));
            maps.push(Arc::new(bpf_map));
        }

        // Fill initial data for data-section maps (.rodata, .data, etc.)
        for map in maps.iter_mut() {
            if let Some(data) = &map.spec.initial_data {
                let key = 0u32.to_ne_bytes();
                map.repr
                    .update(&key, data)
                    .map_err(|source| PrepareError::InitialDataWrite {
                        name: map.spec.name.clone(),
                        source,
                    })?;
            }
        }
        drop(maps);

        // Patch each deferred relocation with its runtime-assigned map FD. Maps match
        // by (sec_idx, sec_offset), data sections match by sec_idx alone and
        // additionally write the in-section offset into the next insn.
        for (&insn_offset, deferred) in &prog.deferred {
            let insn = prog
                .insns
                .get_mut(insn_offset)
                .ok_or(PrepareError::InvalidInstructionOffset { insn_offset })?;

            match *deferred {
                Deferred::Map { sec_idx, addr } => {
                    let (_, fd) = maps_fds
                        .iter()
                        .find(|(spec, _)| {
                            spec.sec_idx == sec_idx.0 && spec.sec_offset == addr as u32
                        })
                        .ok_or(PrepareError::UnresolvedMapRelo {
                            insn_off: insn_offset,
                            section: sec_idx,
                            sec_offset: addr,
                        })?;

                    insn.with_src_reg(BPF_PSEUDO_MAP_FD);
                    insn.with_imm(*fd);
                }
                Deferred::Data { sec_idx, offset } => {
                    let (_, fd) = maps_fds
                        .iter()
                        .find(|(spec, _)| spec.sec_idx == sec_idx.0)
                        .ok_or(PrepareError::UnknownDataReloSection { section: sec_idx })?;

                    insn.with_src_reg(BPF_PSEUDO_MAP_VALUE);
                    insn.with_imm(*fd);

                    let next = prog.insns.get_mut(insn_offset + 1).ok_or(
                        PrepareError::InvalidInstructionOffset {
                            insn_offset: insn_offset + 1,
                        },
                    )?;
                    next.with_imm(offset as i32);
                }
            }
        }

        let prog = Arc::new(prog);
        let verifier = Verifier::new(self, prog.clone(), verifier_config).map_err(|source| {
            PrepareError::Verifier {
                source,
                prog: prog.clone(),
            }
        })?;
        let verification_output = verifier.run().map_err(|source| PrepareError::Verifier {
            source,
            prog: prog.clone(),
        })?;

        Ok(PreparedProgram::new(
            self.clone(),
            prog,
            verification_output,
        ))
    }
}
