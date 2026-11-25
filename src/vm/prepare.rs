#![allow(clippy::unwrap_used, reason = "Mutex::lock only fails if poisoned")]

use std::sync::Arc;

use super::{MapReuseStrategy, PreparedProgram, Vm};
use crate::{
    btf::Btf,
    error::PrepareError,
    isa::mem::{BPF_PSEUDO_MAP_IDX, BPF_PSEUDO_MAP_IDX_VALUE},
    maps::{BpfMap, MapPinning, MapRepr, MapSpec},
    object::{Deferred, EbpfProgram},
    verifier::{Verifier, VerifierConfig},
};

impl Vm {
    /// Hooks an [`EbpfProgram`] into the Vm so it can be run. Every map the
    /// program declares is bound to a slot (see [`Vm::bind_map`]), `ld_imm64`
    /// relocations are patched with those slots, and the verifier walks every
    /// reachable instruction.
    ///
    /// Maps are private to the load by default and live as long as the
    /// returned program, so two programs can each declare a map with the same
    /// name. A map declaring `pinning = LIBBPF_PIN_BY_NAME` is shared through
    /// the Vm's pinned namespace instead, and [`MapReuseStrategy::MatchByName`]
    /// pins every map that way.
    ///
    /// Nothing reaches the Vm until the program has verified, so a failed load
    /// has nothing to undo.
    pub fn prepare(
        self: &Arc<Vm>,
        mut prog: EbpfProgram,
        map_reuse: MapReuseStrategy,
        verifier_config: &VerifierConfig,
    ) -> Result<Arc<PreparedProgram>, PrepareError> {
        let bound = prog
            .maps
            .iter()
            .map(|spec| self.bind_map(spec, &prog.btf, map_reuse))
            .collect::<Result<Vec<_>, _>>()?;

        patch_map_relocations(&mut prog)?;

        let prog = Arc::new(prog);
        let slots: Vec<_> = bound.iter().map(|b| b.map.clone()).collect();
        let verify_err = |source| PrepareError::Verifier {
            source,
            prog: prog.clone(),
        };
        let verification_output = Verifier::new(&slots, prog.clone(), verifier_config)
            .map_err(verify_err)?
            .run()
            .map_err(verify_err)?;

        let maps = self.commit_pins(bound)?;
        Ok(PreparedProgram::new(
            self.clone(),
            prog,
            verification_output,
            maps,
        ))
    }

    /// Picks the map one declaration binds to.
    ///
    /// A pinned declaration reuses the map already pinned under its name, once
    /// [`check_compat`] agrees they describe the same map. Anything else gets
    /// a map of its own. Data sections are never pinned, each load gets its own
    /// copy filled with the section's bytes.
    fn bind_map(
        &self,
        spec: &MapSpec,
        btf: &Arc<Btf>,
        map_reuse: MapReuseStrategy,
    ) -> Result<Bound, PrepareError> {
        let pin = !spec.is_data_section()
            && (spec.pinning == MapPinning::ByName || map_reuse == MapReuseStrategy::MatchByName);

        if pin && let Some(existing) = self.pinned.lock().unwrap().get(&spec.name).cloned() {
            check_compat(&existing, spec, btf)?;
            return Ok(Bound {
                map: existing,
                new_pin: false,
            });
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

        Ok(Bound {
            map: Arc::new(BpfMap {
                repr,
                spec: spec.clone(),
                btf: btf.clone(),
            }),
            new_pin: pin,
        })
    }

    /// Pins the maps this load created for pinned declarations, and returns
    /// the program's final slots.
    ///
    /// Another load may have pinned the same name since [`Vm::bind_map`]
    /// looked. The slot then switches to that map, which is safe because
    /// [`check_compat`] only lets through maps with the same layout the
    /// verifier already checked against. Every pin is checked before any is
    /// inserted, so a mismatch leaves the namespace untouched.
    fn commit_pins(&self, bound: Vec<Bound>) -> Result<Vec<Arc<BpfMap>>, PrepareError> {
        let mut pinned = self.pinned.lock().unwrap();
        let mut staged: Vec<Arc<BpfMap>> = Vec::new();
        let mut slots = Vec::with_capacity(bound.len());

        for Bound { map, new_pin } in bound {
            if !new_pin {
                slots.push(map);
                continue;
            }

            let name = &map.spec.name;
            let existing = pinned
                .get(name)
                .or_else(|| staged.iter().find(|m| &m.spec.name == name));
            match existing {
                Some(existing) => {
                    check_compat(existing, &map.spec, &map.btf)?;
                    slots.push(existing.clone());
                }
                None => {
                    staged.push(map.clone());
                    slots.push(map);
                }
            }
        }

        for map in staged {
            pinned.insert(map.spec.name.clone(), map);
        }
        Ok(slots)
    }
}

/// A map picked for one slot, before the load commits.
struct Bound {
    map: Arc<BpfMap>,
    /// Created by this load for a pinned declaration, to be pinned once the
    /// program verifies.
    new_pin: bool,
}

/// Points each deferred relocation at the slot of the map it targets. A map's
/// slot is its position in [`EbpfProgram::maps`]. Maps match by (sec_idx,
/// sec_offset), data sections by sec_idx alone, and they also write the
/// in-section offset into the next insn.
fn patch_map_relocations(prog: &mut EbpfProgram) -> Result<(), PrepareError> {
    for (&insn_offset, deferred) in &prog.deferred {
        let (src_reg, slot) = match *deferred {
            Deferred::Map { sec_idx, addr } => {
                let slot = prog
                    .maps
                    .iter()
                    .position(|spec| spec.sec_idx == sec_idx.0 && spec.sec_offset == addr as u32)
                    .ok_or(PrepareError::UnresolvedMapRelo {
                        insn_off: insn_offset,
                        section: sec_idx,
                        sec_offset: addr,
                    })?;
                (BPF_PSEUDO_MAP_IDX, slot)
            }
            Deferred::Data { sec_idx, offset } => {
                let slot = prog
                    .maps
                    .iter()
                    .position(|spec| spec.sec_idx == sec_idx.0)
                    .ok_or(PrepareError::UnknownDataReloSection { section: sec_idx })?;

                let next = prog.insns.get_mut(insn_offset + 1).ok_or(
                    PrepareError::InvalidInstructionOffset {
                        insn_offset: insn_offset + 1,
                    },
                )?;
                next.with_imm(offset as i32);
                (BPF_PSEUDO_MAP_IDX_VALUE, slot)
            }
        };

        let insn = prog
            .insns
            .get_mut(insn_offset)
            .ok_or(PrepareError::InvalidInstructionOffset { insn_offset })?;
        insn.with_src_reg(src_reg);
        insn.with_imm(slot as i32);
    }
    Ok(())
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

    const RET_0: [Insn; 2] = [Insn(0xb7), Insn(0x95)];

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

    /// Runs `insns`, declaring `maps` without touching them.
    fn prog(insns: &[Insn], maps: Vec<MapSpec>) -> EbpfProgram {
        EbpfProgram {
            insns: insns.to_vec(),
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
        vm.prepare(prog(&RET_0, maps), reuse, &VerifierConfig::default())
    }

    fn slot(prog: &PreparedProgram, name: &str) -> Arc<BpfMap> {
        prog.maps
            .iter()
            .find(|map| map.spec.name == name)
            .cloned()
            .unwrap()
    }

    fn pins(vm: &Vm) -> Vec<String> {
        vm.pinned.lock().unwrap().keys().cloned().collect()
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

        assert!(!Arc::ptr_eq(&slot(&a, "events"), &slot(&b, "events")));
        assert!(pins(&vm).is_empty());
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

        assert!(Arc::ptr_eq(&slot(&a, "counters"), &slot(&b, "counters")));
        assert_eq!(pins(&vm), ["counters"]);
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

        assert!(Arc::ptr_eq(&slot(&a, "counters"), &slot(&b, "counters")));
    }

    #[test]
    fn incompatible_pin_is_rejected() {
        let vm = Vm::new();
        let first = load(
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
        let pinned = vm.pinned.lock().unwrap().get("counters").cloned().unwrap();
        assert!(Arc::ptr_eq(&pinned, &slot(&first, "counters")));
    }

    #[test]
    fn failed_map_creation_pins_nothing() {
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

        assert!(pins(&vm).is_empty());
    }

    #[test]
    fn failed_verification_pins_nothing() {
        let vm = Vm::new();
        // r1 = map_by_idx(7), with only slot 0 declared.
        let ld_missing_slot = Insn(0x18 | 1 << 8 | u64::from(BPF_PSEUDO_MAP_IDX) << 12 | 7 << 32);
        let insns = [ld_missing_slot, Insn(0), RET_0[0], RET_0[1]];
        let bad = prog(&insns, vec![hash("counters", MapPinning::ByName)]);

        let err = vm
            .prepare(bad, MapReuseStrategy::None, &VerifierConfig::default())
            .err()
            .expect("loading a slot the program doesn't have must fail verification");

        assert!(err.to_string().contains("non-existing map slot"), "{err}");
        assert!(pins(&vm).is_empty());
    }

    #[test]
    fn one_load_pinning_a_name_twice_gets_one_map() {
        let vm = Vm::new();
        let mut twin = hash("counters", MapPinning::ByName);
        twin.sec_offset = 64;

        let prog = load(
            &vm,
            vec![hash("counters", MapPinning::ByName), twin],
            MapReuseStrategy::None,
        )
        .expect("both declarations describe the same map");

        assert!(matches!(prog.maps.as_slice(), [a, b] if Arc::ptr_eq(a, b)));
        assert_eq!(pins(&vm), ["counters"]);
    }

    #[test]
    fn dropping_a_program_frees_its_private_maps() {
        let vm = Vm::new();
        let prog = load(
            &vm,
            vec![
                hash("events", MapPinning::None),
                hash("counters", MapPinning::ByName),
            ],
            MapReuseStrategy::None,
        )
        .expect("load must succeed");
        let events = Arc::downgrade(&slot(&prog, "events"));
        let counters = Arc::downgrade(&slot(&prog, "counters"));

        drop(prog);

        assert!(events.upgrade().is_none());
        assert!(counters.upgrade().is_some(), "the pin keeps it alive");
    }

    #[test]
    fn unpinned_name_gets_a_fresh_map() {
        let vm = Vm::new();
        let old = load(
            &vm,
            vec![hash("counters", MapPinning::ByName)],
            MapReuseStrategy::None,
        )
        .expect("first load must succeed");

        assert!(vm.unpin("counters"));
        let new = load(
            &vm,
            vec![hash("counters", MapPinning::ByName)],
            MapReuseStrategy::None,
        )
        .expect("second load must pin a new map");

        assert!(!Arc::ptr_eq(
            &slot(&old, "counters"),
            &slot(&new, "counters")
        ));
        assert!(!vm.unpin("missing"));
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

        assert!(!Arc::ptr_eq(&slot(&a, ".rodata"), &slot(&b, ".rodata")));
        assert!(pins(&vm).is_empty());
    }
}
