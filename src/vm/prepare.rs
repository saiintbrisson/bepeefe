#![allow(clippy::unwrap_used, reason = "Mutex::lock only fails if poisoned")]

use std::sync::Arc;

use super::{MapReuseStrategy, MapTable, PreparedProgram, Vm};
use crate::{
    btf::Btf,
    error::PrepareError,
    isa::mem::{BPF_PSEUDO_MAP_FD, BPF_PSEUDO_MAP_VALUE},
    maps::{BpfMap, MapPinning, MapRepr, MapSpec},
    object::{Deferred, EbpfProgram},
    verifier::{Verifier, VerifierConfig},
};

impl Vm {
    /// Hooks an [`EbpfProgram`] into the Vm so it can be run. We do three main
    /// things: maps are bound to fds (see [`bind_map`]), `ld_imm64`
    /// relocations are patched with those fds, and the verifier walks every
    /// reachable instruction.
    ///
    /// Maps are private to the load by default, so two programs can each
    /// declare a map with the same name. A map declaring `pinning =
    /// LIBBPF_PIN_BY_NAME` is shared through the Vm's pinned namespace
    /// instead, and [`MapReuseStrategy::MatchByName`] pins every map that way.
    ///
    /// A failed load leaves the Vm as it found it, maps and pins included.
    pub fn prepare(
        self: &Arc<Vm>,
        prog: EbpfProgram,
        map_reuse: MapReuseStrategy,
        verifier_config: &VerifierConfig,
    ) -> Result<Arc<PreparedProgram>, PrepareError> {
        let rollback = self.maps.lock().unwrap().by_fd.len();
        self.prepare_inner(prog, map_reuse, verifier_config)
            .inspect_err(|_| self.maps.lock().unwrap().truncate(rollback))
    }

    fn prepare_inner(
        self: &Arc<Vm>,
        mut prog: EbpfProgram,
        map_reuse: MapReuseStrategy,
        verifier_config: &VerifierConfig,
    ) -> Result<Arc<PreparedProgram>, PrepareError> {
        let mut maps_fds = Vec::with_capacity(prog.maps.len());
        {
            let mut table = self.maps.lock().unwrap();
            for spec in &prog.maps {
                let fd = bind_map(&mut table, spec, &prog.btf, map_reuse)?;
                maps_fds.push((spec, fd));
            }
        }

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

        let maps = maps_fds
            .iter()
            .map(|(spec, fd)| (spec.name.clone(), *fd))
            .collect();

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
            maps,
        ))
    }
}

/// Binds one map declaration to an fd.
///
/// A pinned declaration reuses the map already pinned under its name, once
/// [`check_compat`] agrees they describe the same map, and pins the map it
/// creates otherwise. Data sections are never pinned, each load gets its own
/// copy filled with the section's bytes.
fn bind_map(
    table: &mut MapTable,
    spec: &MapSpec,
    btf: &Arc<Btf>,
    map_reuse: MapReuseStrategy,
) -> Result<i32, PrepareError> {
    let pinned = !spec.is_data_section()
        && (spec.pinning == MapPinning::ByName || map_reuse == MapReuseStrategy::MatchByName);

    if pinned
        && let Some(existing) = table
            .pinned
            .get(&spec.name)
            .and_then(|&fd| table.by_fd.get(fd as usize))
    {
        check_compat(existing, spec, btf)?;
        return Ok(existing.fd);
    }

    let repr = MapRepr::create_from_btf(btf, spec)?;
    if let Some(data) = &spec.initial_data {
        repr.update(&0u32.to_ne_bytes(), data).map_err(|source| {
            PrepareError::InitialDataWrite {
                name: spec.name.clone(),
                source,
            }
        })?;
    }

    let fd = table.by_fd.len() as i32;
    table.by_fd.push(Arc::new(BpfMap {
        fd,
        repr,
        spec: spec.clone(),
        btf: btf.clone(),
    }));
    if pinned {
        table.pinned.insert(spec.name.clone(), fd);
    }
    Ok(fd)
}

/// Rejects reusing a pinned map that `spec` describes differently. These are
/// the attributes libbpf compares before reusing a pin.
fn check_compat(pinned: &BpfMap, spec: &MapSpec, btf: &Btf) -> Result<(), PrepareError> {
    let existing = &pinned.spec;
    let attrs = [
        ("type", existing.r#type, spec.r#type),
        (
            "key size",
            existing.resolved_key_size(&pinned.btf),
            spec.resolved_key_size(btf),
        ),
        (
            "value size",
            existing.resolved_value_size(&pinned.btf),
            spec.resolved_value_size(btf),
        ),
        ("max entries", existing.max_entries, spec.max_entries),
        ("flags", existing.map_flags, spec.map_flags),
        ("map extra", existing.map_extra, spec.map_extra),
    ];

    for (attr, pinned, declared) in attrs {
        let (pinned, declared) = (pinned.unwrap_or(0), declared.unwrap_or(0));
        if pinned != declared {
            return Err(PrepareError::IncompatiblePinnedMap {
                name: spec.name.clone(),
                attr,
                pinned,
                declared,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use object::SectionIndex;

    use super::*;
    use crate::{
        isa::Insn,
        maps::{BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_HASH},
        object::FunctionSignature,
    };

    fn hash(name: &str, pinning: MapPinning) -> MapSpec {
        MapSpec {
            name: name.into(),
            r#type: Some(BPF_MAP_TYPE_HASH),
            key_size: Some(4),
            value_size: Some(8),
            max_entries: Some(16),
            pinning,
            ..Default::default()
        }
    }

    /// `r0 = 0; exit`, declaring `maps` without touching them.
    fn prog(maps: Vec<MapSpec>) -> EbpfProgram {
        EbpfProgram {
            insns: vec![Insn(0xb7), Insn(0x95)],
            func: FunctionSignature {
                name: "entry".into(),
                btf_id: None,
                is_global: true,
                params_types: Vec::new(),
                return_type: None,
                section_idx: SectionIndex(0),
                section_offset: 0,
                size: 0,
            },
            maps,
            btf: Arc::new(Btf::default()),
            hook: None,
            deferred: BTreeMap::new(),
            line_info: BTreeMap::new(),
            subprogs: BTreeMap::new(),
        }
    }

    fn load(
        vm: &Arc<Vm>,
        maps: Vec<MapSpec>,
        reuse: MapReuseStrategy,
    ) -> Result<Arc<PreparedProgram>, PrepareError> {
        vm.prepare(prog(maps), reuse, &VerifierConfig::default())
    }

    fn fd_of(prog: &PreparedProgram, name: &str) -> Option<i32> {
        prog.maps.iter().find(|(n, _)| n == name).map(|(_, fd)| *fd)
    }

    #[test]
    fn unpinned_maps_with_the_same_name_stay_private() {
        let vm = Vm::new();
        let a = load(
            &vm,
            vec![hash("events", MapPinning::None)],
            MapReuseStrategy::None,
        )
        .expect("first load must succeed");
        let b = load(
            &vm,
            vec![hash("events", MapPinning::None)],
            MapReuseStrategy::None,
        )
        .expect("a second map named events must not collide");

        assert_ne!(fd_of(&a, "events"), fd_of(&b, "events"));
        assert!(vm.maps.lock().unwrap().pinned.is_empty());
    }

    #[test]
    fn pinned_maps_are_shared() {
        let vm = Vm::new();
        let a = load(
            &vm,
            vec![hash("counters", MapPinning::ByName)],
            MapReuseStrategy::None,
        )
        .expect("first load must succeed");
        let b = load(
            &vm,
            vec![hash("counters", MapPinning::ByName)],
            MapReuseStrategy::None,
        )
        .expect("a compatible pin must be reused");

        assert_eq!(fd_of(&a, "counters"), fd_of(&b, "counters"));
        assert_eq!(vm.maps.lock().unwrap().by_fd.len(), 1);
    }

    #[test]
    fn match_by_name_pins_every_map() {
        let vm = Vm::new();
        let a = load(
            &vm,
            vec![hash("counters", MapPinning::None)],
            MapReuseStrategy::MatchByName,
        )
        .expect("first load must succeed");
        let b = load(
            &vm,
            vec![hash("counters", MapPinning::None)],
            MapReuseStrategy::MatchByName,
        )
        .expect("second load must reuse the map");

        assert_eq!(fd_of(&a, "counters"), fd_of(&b, "counters"));
    }

    #[test]
    fn incompatible_pin_is_rejected() {
        let vm = Vm::new();
        load(
            &vm,
            vec![hash("counters", MapPinning::ByName)],
            MapReuseStrategy::None,
        )
        .expect("first load must succeed");

        let mut bigger = hash("counters", MapPinning::ByName);
        bigger.max_entries = Some(32);
        let err = load(&vm, vec![bigger], MapReuseStrategy::None)
            .err()
            .expect("a pin with a different max_entries must not be reused");

        assert!(matches!(
            err,
            PrepareError::IncompatiblePinnedMap {
                attr: "max entries",
                pinned: 16,
                declared: 32,
                ..
            }
        ));
        assert_eq!(vm.maps.lock().unwrap().by_fd.len(), 1);
    }

    #[test]
    fn failed_load_drops_its_maps_and_pins() {
        let vm = Vm::new();
        let mut broken = hash("broken", MapPinning::None);
        broken.r#type = None;

        load(
            &vm,
            vec![hash("counters", MapPinning::ByName), broken],
            MapReuseStrategy::None,
        )
        .err()
        .expect("a map without a type must fail the load");

        let table = vm.maps.lock().unwrap();
        assert!(table.by_fd.is_empty());
        assert!(table.pinned.is_empty());
    }

    #[test]
    fn data_sections_are_never_pinned() {
        let rodata = || MapSpec {
            name: ".rodata".into(),
            r#type: Some(BPF_MAP_TYPE_ARRAY),
            key_size: Some(4),
            value_size: Some(4),
            max_entries: Some(1),
            initial_data: Some(vec![1, 2, 3, 4]),
            ..Default::default()
        };

        let vm = Vm::new();
        let a = load(&vm, vec![rodata()], MapReuseStrategy::MatchByName)
            .expect("first load must succeed");
        let b = load(&vm, vec![rodata()], MapReuseStrategy::MatchByName)
            .expect("second load must get its own copy");

        assert_ne!(fd_of(&a, ".rodata"), fd_of(&b, ".rodata"));
        assert!(vm.maps.lock().unwrap().pinned.is_empty());
    }
}
