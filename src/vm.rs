#![allow(clippy::unwrap_used, reason = "Mutex::lock only fails if poisoned")]

use std::{
    collections::BTreeMap,
    ops::DerefMut,
    sync::{Arc, Mutex},
};

use crate::maps::BpfMap;

mod cpu;
mod datasec;
pub(crate) mod helpers;
mod map_handle;
mod prepare;
mod prepared;
pub(crate) mod ptr;
mod task;
mod world;

pub use cpu::{Cpu, CtxImage};
pub use datasec::DatasecHandle;
pub use map_handle::MapHandle;
pub use prepared::PreparedProgram;
pub use task::{Task, TaskError};
pub use world::World;

pub struct Vm {
    pub(super) maps: Mutex<MapTable>,
    world: Mutex<World>,
}

/// Every map the Vm created, indexed by fd, plus the names programs can share.
#[derive(Default)]
pub(super) struct MapTable {
    pub(super) by_fd: Vec<Arc<BpfMap>>,
    pub(super) pinned: BTreeMap<String, i32>,
}

impl MapTable {
    /// Drops every map from `fd` onwards, along with any pin pointing at one.
    fn truncate(&mut self, fd: usize) {
        self.by_fd.truncate(fd);
        self.pinned.retain(|_, pinned| (*pinned as usize) < fd);
    }
}

impl Vm {
    pub fn new() -> Arc<Self> {
        Self::with_world(World::default())
    }

    pub fn with_world(world: World) -> Arc<Self> {
        Arc::new(Self {
            maps: Default::default(),
            world: Mutex::new(world),
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
        maps.by_fd
            .get(fd as usize)
            .cloned()
            .unwrap_or_else(|| panic!("unknown map fd {fd}"))
    }

    pub(crate) fn has_map(&self, fd: u16) -> bool {
        self.maps.lock().unwrap().by_fd.get(fd as usize).is_some()
    }

    /// The mutable state shared across invocations.
    pub fn world(&self) -> impl DerefMut<Target = World> + '_ {
        self.world.lock().unwrap()
    }

    /// A map shared under `name` by every program that pins it. Maps a single
    /// program owns are accessed through [`PreparedProgram::map`] instead.
    pub fn pinned_map(&self, name: &str) -> Option<MapHandle> {
        let maps = self.maps.lock().unwrap();
        let fd = *maps.pinned.get(name)?;
        MapHandle::new(maps.by_fd.get(fd as usize)?.clone())
    }

    pub fn pinned_maps(&self) -> Vec<MapHandle> {
        let maps = self.maps.lock().unwrap();
        maps.pinned
            .values()
            .filter_map(|&fd| maps.by_fd.get(fd as usize).cloned())
            .filter_map(MapHandle::new)
            .collect()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MapReuseStrategy {
    /// Only maps declaring `pinning = LIBBPF_PIN_BY_NAME` are shared. Every
    /// other map is created fresh for the program load.
    #[default]
    None,
    /// Every map is treated as pinned by name, so it binds to a compatible map
    /// another program already pinned under that name. Data sections stay
    /// private either way.
    MatchByName,
}

pub(crate) const STACK_SIZE: usize = 512;
pub(crate) const MAX_CALL_FRAMES: usize = 8;
