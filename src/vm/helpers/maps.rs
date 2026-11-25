use crate::verifier::{RegisterState, ScalarRange};
use std::sync::Arc;

use crate::maps::BpfMap;

use super::args::{Call, Ctx, In, Key, Map, Num, Value, ValueOut};
use super::{ArgRegs, BpfHelper, map_ops};

fn status<E>(res: Result<(), E>) -> u64 {
    match res {
        Ok(()) => 0,
        Err(_) => -1i64 as u64,
    }
}

pub struct MapLookupElem;
impl MapLookupElem {
    pub const ID: i32 = 1;
}
impl BpfHelper for MapLookupElem {
    type Args = (Map, Key);

    fn name(&self) -> &'static str {
        "bpf_map_lookup_elem"
    }

    fn exec(&self, _: &mut Call<'_>, (map, key): Self::Args) -> u64 {
        map_ops::lookup_elem(&map, &key.0).unwrap_or_default()
    }

    fn retval(&self, maps: &[Arc<BpfMap>], regs: ArgRegs) -> Result<RegisterState, &'static str> {
        let RegisterState::PtrToMap { map_idx } = regs.get(1) else {
            return Err("map_lookup_elem: R1 must be PtrToMap");
        };
        let map = maps.get(map_idx as usize).ok_or("unknown map slot")?;
        if map.spec.r#type == Some(crate::maps::BPF_MAP_TYPE_ARRAY) {
            Ok(RegisterState::PtrToMapValue {
                map_idx,
                offset: ScalarRange::exact(0),
            })
        } else {
            Ok(RegisterState::PtrToMapValueOrNull { map_idx })
        }
    }
}

pub struct MapUpdateElem;
impl MapUpdateElem {
    pub const ID: i32 = 2;
}
impl BpfHelper for MapUpdateElem {
    type Args = (Map, Key, Value, Num);

    fn name(&self) -> &'static str {
        "bpf_map_update_elem"
    }

    fn exec(&self, _: &mut Call<'_>, (map, key, value, _flags): Self::Args) -> u64 {
        status(map.map.repr.update(&key.0, &value.0))
    }
}

pub struct MapDeleteElem;
impl MapDeleteElem {
    pub const ID: i32 = 3;
}
impl BpfHelper for MapDeleteElem {
    type Args = (Map, Key);

    fn name(&self) -> &'static str {
        "bpf_map_delete_elem"
    }

    fn exec(&self, _: &mut Call<'_>, (map, key): Self::Args) -> u64 {
        status(map.map.repr.delete(&key.0))
    }
}

pub struct MapPushElem;
impl MapPushElem {
    pub const ID: i32 = 87;
}
impl BpfHelper for MapPushElem {
    type Args = (Map, Value);

    fn name(&self) -> &'static str {
        "bpf_map_push_elem"
    }

    fn exec(&self, _: &mut Call<'_>, (map, value): Self::Args) -> u64 {
        status(map.map.repr.push(&value.0))
    }
}

pub struct MapPopElem;
impl MapPopElem {
    pub const ID: i32 = 88;
}
impl BpfHelper for MapPopElem {
    type Args = (Map, ValueOut);

    fn name(&self) -> &'static str {
        "bpf_map_pop_elem"
    }

    fn exec(&self, cx: &mut Call<'_>, (map, dst): Self::Args) -> u64 {
        status(map_ops::pop(cx, &map, &dst.0))
    }
}

pub struct MapPeekElem;
impl MapPeekElem {
    pub const ID: i32 = 89;
}
impl BpfHelper for MapPeekElem {
    type Args = (Map, ValueOut);

    fn name(&self) -> &'static str {
        "bpf_map_peek_elem"
    }

    fn exec(&self, cx: &mut Call<'_>, (map, dst): Self::Args) -> u64 {
        status(map_ops::peek(cx, &map, &dst.0))
    }
}

pub struct PerfEventOutput;
impl PerfEventOutput {
    pub const ID: i32 = 25;
}
impl BpfHelper for PerfEventOutput {
    type Args = (Ctx, Map, Num, In);

    fn name(&self) -> &'static str {
        "bpf_perf_event_output"
    }

    fn exec(&self, cx: &mut Call<'_>, (_, map, flags, data): Self::Args) -> u64 {
        status(map_ops::perf_event_output(cx, &map, flags.0, &data.0))
    }

    fn retval(&self, maps: &[Arc<BpfMap>], regs: ArgRegs) -> Result<RegisterState, &'static str> {
        let RegisterState::PtrToMap { map_idx } = regs.get(2) else {
            return Err("perf_event_output: R2 must be PtrToMap");
        };
        let map = maps.get(map_idx as usize).ok_or("unknown map slot")?;
        if map.spec.r#type != Some(crate::maps::BPF_MAP_TYPE_PERF_EVENT_ARRAY) {
            return Err("perf_event_output: R2 map must be BPF_MAP_TYPE_PERF_EVENT_ARRAY");
        }
        Ok(RegisterState::Scalar(crate::verifier::Scalar::Unknown))
    }
}
