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
    /// Maps shared by name across program loads. Every other map lives only as
    /// long as the programs that hold it.
    pub(super) pinned: Mutex<BTreeMap<String, Arc<BpfMap>>>,
    world: Mutex<World>,
}

impl Vm {
    pub fn new() -> Arc<Self> {
        Self::with_world(World::default())
    }

    pub fn with_world(world: World) -> Arc<Self> {
        Arc::new(Self {
            pinned: Default::default(),
            world: Mutex::new(world),
        })
    }

    /// The mutable state shared across invocations.
    pub fn world(&self) -> impl DerefMut<Target = World> + '_ {
        self.world.lock().unwrap()
    }

    /// A map shared under `name` by every program that pins it. Maps a single
    /// program owns are accessed through [`PreparedProgram::map`] instead.
    pub fn pinned_map(&self, name: &str) -> Option<MapHandle> {
        MapHandle::new(self.pinned.lock().unwrap().get(name)?.clone())
    }

    pub fn pinned_maps(&self) -> Vec<MapHandle> {
        self.pinned
            .lock()
            .unwrap()
            .values()
            .cloned()
            .filter_map(MapHandle::new)
            .collect()
    }

    /// Removes the pin, so the next load declaring `name` creates a new map.
    /// Programs already bound to the old map keep it until they're dropped.
    pub fn unpin(&self, name: &str) -> bool {
        self.pinned.lock().unwrap().remove(name).is_some()
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
