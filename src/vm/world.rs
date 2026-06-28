use std::sync::Arc;

/// VM state shared across every invocation. The clock, probe-readable memory,
/// the current CPU, and the RNG. An emulator mutates these between runs through
/// `Vm::world`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct World {
    pub ktime_ns: u64,
    pub cpu: u32,
    /// Kernel-space memory reachable by `bpf_probe_read_kernel`.
    pub kernel: Arc<[u8]>,
    /// User-space memory reachable by `bpf_probe_read_user`.
    pub user: Arc<[u8]>,
    /// xorshift RNG behind `bpf_get_prandom_u32`. Reseed by assigning
    /// a nonzero value.
    pub rng_state: u32,
}

impl Default for World {
    fn default() -> Self {
        Self {
            ktime_ns: 0,
            cpu: 0,
            kernel: Arc::default(),
            user: Arc::default(),
            rng_state: 0xDEAD_BEEF,
        }
    }
}

impl World {
    pub fn with_kernel(mut self, bytes: impl Into<Arc<[u8]>>) -> Self {
        self.kernel = bytes.into();
        self
    }

    pub fn with_user(mut self, bytes: impl Into<Arc<[u8]>>) -> Self {
        self.user = bytes.into();
        self
    }

    /// Advances the xorshift cursor and returns the new value.
    pub fn prandom_u32(&mut self) -> u32 {
        let mut s = self.rng_state;
        s ^= s << 13;
        s ^= s >> 17;
        s ^= s << 5;
        self.rng_state = s;
        s
    }
}
