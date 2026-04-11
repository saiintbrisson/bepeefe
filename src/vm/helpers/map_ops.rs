use crate::capture::Event;
use crate::error::RuntimeError;
use crate::vm::{cpu::Cpu, ptr::TaggedPtr};

/// Lower 32 bits of `flags` carry the slot index for
/// `bpf_perf_event_output` (and friends). `BPF_F_CURRENT_CPU` is the
/// flag that asks the helper to use the current CPU's slot.
pub(crate) const BPF_F_INDEX_MASK: u64 = u32::MAX as u64;
pub(crate) const BPF_F_CURRENT_CPU: u64 = BPF_F_INDEX_MASK;

pub(crate) fn lookup_elem(state: &Cpu, map_fd: u16, key: u64) -> Option<u64> {
    let map = state.get_map(map_fd);
    let key = state.read_bytes(key, map.repr.key_size());
    let elem = map.repr.lookup(&key)?;
    Some(TaggedPtr::map(map_fd, elem as u32))
}

pub(crate) fn update(
    state: &Cpu,
    map_fd: u16,
    key_ptr: u64,
    value_ptr: u64,
) -> Result<(), RuntimeError> {
    let map = state.get_map(map_fd);
    let key = state.read_bytes(key_ptr, map.repr.key_size());
    let value = state.read_bytes(value_ptr, map.repr.value_size());
    map.repr.update(&key, &value)
}

pub(crate) fn delete(state: &Cpu, map_fd: u16, key_ptr: u64) -> Result<(), RuntimeError> {
    let map = state.get_map(map_fd);
    let key = state.read_bytes(key_ptr, map.repr.key_size());
    map.repr.delete(&key)
}

pub(crate) fn push(state: &Cpu, map_fd: u16, value_ptr: u64) -> Result<(), RuntimeError> {
    let map = state.get_map(map_fd);
    let value = state.read_bytes(value_ptr, map.repr.value_size());
    map.repr.push(&value)
}

pub(crate) fn pop(state: &mut Cpu, map_fd: u16, dest_ptr: u64) -> Result<(), RuntimeError> {
    let map = state.get_map(map_fd);
    let value_size = map.repr.value_size();
    let offset = map.repr.pop().ok_or(RuntimeError::MapKeyNotFound)?;
    let bytes = map
        .repr
        .read_bytes(offset, value_size)
        .ok_or(RuntimeError::MapKeyNotFound)?;
    state.write(dest_ptr, &bytes);
    Ok(())
}

pub(crate) fn peek(state: &mut Cpu, map_fd: u16, dest_ptr: u64) -> Result<(), RuntimeError> {
    let map = state.get_map(map_fd);
    let value_size = map.repr.value_size();
    let offset = map.repr.peek().ok_or(RuntimeError::MapKeyNotFound)?;
    let bytes = map
        .repr
        .read_bytes(offset, value_size)
        .ok_or(RuntimeError::MapKeyNotFound)?;
    state.write(dest_ptr, &bytes);
    Ok(())
}

/// Resolves the slot's stored fd and emits the payload via the host
/// capture impl. The map itself only stores the `cpu -> fd` mapping,
/// the actual data goes out as an [`Event::PerfEventOutput`].
pub(crate) fn perf_event_output(
    state: &Cpu,
    map_fd: u16,
    flags: u64,
    data_ptr: u64,
    size: u32,
) -> Result<(), RuntimeError> {
    let index = match flags & BPF_F_INDEX_MASK {
        BPF_F_CURRENT_CPU => state.env().cpu,
        i => i as u32,
    };
    let map = state.get_map(map_fd);
    let key = index.to_ne_bytes();
    let offset = map.repr.lookup(&key).ok_or(RuntimeError::MapKeyNotFound)?;
    let fd_bytes = map
        .repr
        .read::<4>(offset)
        .ok_or(RuntimeError::MapKeyNotFound)?;
    let fd = u32::from_ne_bytes(fd_bytes);
    if let Some(cap) = state.capture() {
        let data = state.read_bytes(data_ptr, size as usize).into_owned();
        cap.record(Event::PerfEventOutput {
            fd,
            data: data.into(),
        });
    }
    Ok(())
}
