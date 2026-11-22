use crate::capture::Event;
use crate::error::RuntimeError;
use crate::vm::ptr::TaggedPtr;

use super::args::{Call, Map, Out};

/// Lower 32 bits of `flags` carry the slot index for
/// `bpf_perf_event_output` (and friends). `BPF_F_CURRENT_CPU` is the
/// flag that asks the helper to use the current CPU's slot.
pub(crate) const BPF_F_INDEX_MASK: u64 = u32::MAX as u64;
pub(crate) const BPF_F_CURRENT_CPU: u64 = BPF_F_INDEX_MASK;

pub(crate) fn lookup_elem(map: &Map, key: &[u8]) -> Option<u64> {
    let elem = map.map.repr.lookup(key)?;
    Some(TaggedPtr::map(map.fd, elem as u32))
}

pub(crate) fn pop(cx: &mut Call<'_>, map: &Map, dst: &Out) -> Result<(), RuntimeError> {
    let repr = &map.map.repr;
    let offset = repr.pop().ok_or(RuntimeError::MapKeyNotFound)?;
    let bytes = repr
        .read_bytes(offset, repr.value_size())
        .ok_or(RuntimeError::MapKeyNotFound)?;
    cx.write(dst, &bytes);
    Ok(())
}

pub(crate) fn peek(cx: &mut Call<'_>, map: &Map, dst: &Out) -> Result<(), RuntimeError> {
    let repr = &map.map.repr;
    let offset = repr.peek().ok_or(RuntimeError::MapKeyNotFound)?;
    let bytes = repr
        .read_bytes(offset, repr.value_size())
        .ok_or(RuntimeError::MapKeyNotFound)?;
    cx.write(dst, &bytes);
    Ok(())
}

/// Resolves the slot's stored fd and emits the payload via the host
/// capture impl. The map itself only stores the `cpu -> fd` mapping,
/// the actual data goes out as an [`Event::PerfEventOutput`].
pub(crate) fn perf_event_output(
    cx: &Call<'_>,
    map: &Map,
    flags: u64,
    data: &[u8],
) -> Result<(), RuntimeError> {
    let index = match flags & BPF_F_INDEX_MASK {
        BPF_F_CURRENT_CPU => cx.cpu(),
        i => i as u32,
    };
    let repr = &map.map.repr;
    let key = index.to_ne_bytes();
    let offset = repr.lookup(&key).ok_or(RuntimeError::MapKeyNotFound)?;
    let fd_bytes = repr.read::<4>(offset).ok_or(RuntimeError::MapKeyNotFound)?;
    let fd = u32::from_ne_bytes(fd_bytes);
    if let Some(cap) = cx.capture() {
        cap.record(Event::PerfEventOutput {
            pc: cx.pc().saturating_sub(1),
            fd,
            data: data.to_vec().into(),
        });
    }
    Ok(())
}
