#![allow(clippy::unwrap_used, reason = "Mutex::lock only fails if poisoned")]

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU32, Ordering},
};

use crate::maps::BpfMap;

mod cpu;
pub mod env;
pub(crate) mod helpers;
mod map_handle;
mod prepare;
mod prepared;
pub(crate) mod ptr;

pub use cpu::{Cpu, CtxImage};
pub use env::HostEnv;
pub use map_handle::MapHandle;
pub use prepared::PreparedProgram;

pub struct Vm {
    pub(super) maps: Mutex<Vec<Arc<BpfMap>>>,
    rng_state: AtomicU32,
}

impl Vm {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            maps: Default::default(),
            rng_state: AtomicU32::new(0xDEAD_BEEF),
        })
    }

    /// # Panics
    ///
    /// Panics if `fd` is not a known map FD. All runtime callers reach
    /// this through verifier-validated register states; the verifier
    /// itself uses [`Vm::has_map`] to check FDs before they are trusted.
    #[expect(clippy::panic, reason = "caller is expected to run verifier")]
    pub(crate) fn get_map(&self, fd: u16) -> Arc<BpfMap> {
        let maps = self.maps.lock().unwrap();
        maps.get(fd as usize)
            .cloned()
            .unwrap_or_else(|| panic!("unknown map fd {fd}"))
    }

    pub(crate) fn has_map(&self, fd: u16) -> bool {
        self.maps.lock().unwrap().get(fd as usize).is_some()
    }

    pub fn set_rng_seed(&self, seed: u32) {
        self.rng_state.store(seed, Ordering::Release);
    }

    /// Returns a random u32 and updates the RNG
    /// state applying a xorshift.
    // TODO: move to host env
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

    /// Looks up a typed map by name. Returns `None` for untyped
    /// data maps (`.bss`, `.data`, `.rodata`, etc.), those have no
    /// value BTF and can't be read or written through `MapHandle`.
    pub fn map(&self, name: &str) -> Option<MapHandle> {
        let maps = self.maps.lock().unwrap();
        let bpf_map = maps.iter().find(|map| map.spec.name == name)?.clone();
        MapHandle::new(bpf_map)
    }

    /// All typed maps in the VM. Untyped data maps are filtered out.
    pub fn maps(&self) -> Vec<MapHandle> {
        self.maps
            .lock()
            .unwrap()
            .iter()
            .cloned()
            .filter_map(MapHandle::new)
            .collect()
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

pub(crate) const STACK_SIZE: usize = 512;
pub(crate) const MAX_CALL_FRAMES: usize = 8;
