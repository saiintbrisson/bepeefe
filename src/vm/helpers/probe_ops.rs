use crate::vm::{
    cpu::Cpu,
    env::HostEnv,
    ptr::{TaggedPtr, TaggetPtrType},
};

/// Linux `-EFAULT`. Returned when the source pointer can't be read.
const E_FAULT: i64 = -14;

/// Cap on the source scan length for the `_str` variants. Matches the
/// Linux kernel's own cap and prevents a malformed slice from making us
/// read until the region's end.
const STR_CAP: usize = 4096;

fn decode(env: &'_ HostEnv, space: TaggetPtrType, src: u64) -> Option<(usize, &'_ [u8])> {
    let tag = TaggedPtr::try_decode(src)?;
    match (space, tag) {
        (TaggetPtrType::Kernel, TaggedPtr::Kernel { offset }) => {
            Some((offset as usize, env.kernel.as_ref()))
        }
        (TaggetPtrType::User, TaggedPtr::User { offset }) => {
            Some((offset as usize, env.user.as_ref()))
        }
        _ => None,
    }
}

fn read_at(env: &HostEnv, space: TaggetPtrType, src: u64, len: usize) -> Option<Vec<u8>> {
    let (offset, slice) = decode(env, space, src)?;
    let end = offset.checked_add(len)?;
    slice.get(offset..end).map(<[u8]>::to_vec)
}

fn read_str(env: &HostEnv, space: TaggetPtrType, src: u64, cap: usize) -> Option<Vec<u8>> {
    let (offset, slice) = decode(env, space, src)?;
    let region = slice.get(offset..)?;
    let max = cap.saturating_sub(1);
    let mut out: Vec<u8> = region
        .iter()
        .copied()
        .take(max)
        .take_while(|&b| b != 0)
        .collect();
    out.push(0);
    Some(out)
}

/// `bpf_probe_read_{kernel,user}`. Copies `size` bytes from `src` into
/// `dst`. On fault, zeroes `dst` and returns `-EFAULT`, matching Linux.
pub(crate) fn probe_read(
    state: &mut Cpu,
    space: TaggetPtrType,
    dst: u64,
    size: u32,
    src: u64,
) -> i64 {
    let len = size as usize;
    match read_at(state.env(), space, src, len) {
        Some(bytes) => {
            state.write(dst, &bytes);
            0
        }
        None => {
            state.write(dst, &vec![0u8; len]);
            E_FAULT
        }
    }
}

/// `bpf_probe_read_{kernel,user}_str`. Copies up to `size - 1` bytes
/// from `src` into `dst`, stopping at the first NUL, then writes a
/// terminating NUL. Returns the number of bytes written including the
/// NUL, or `-EFAULT` on fault (with `dst` zeroed).
pub(crate) fn probe_read_str(
    state: &mut Cpu,
    space: TaggetPtrType,
    dst: u64,
    size: u32,
    src: u64,
) -> i64 {
    if size == 0 {
        return 0;
    }
    let cap = (size as usize).min(STR_CAP);
    match read_str(state.env(), space, src, cap) {
        Some(bytes) => {
            let n = bytes.len() as i64;
            state.write(dst, &bytes);
            n
        }
        None => {
            state.write(dst, &vec![0u8; size as usize]);
            E_FAULT
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn env_kernel(bytes: &[u8]) -> HostEnv {
        HostEnv::default().with_kernel(Arc::<[u8]>::from(bytes))
    }

    fn env_user(bytes: &[u8]) -> HostEnv {
        HostEnv::default().with_user(Arc::<[u8]>::from(bytes))
    }

    #[test]
    fn read_at_returns_bytes() {
        let env = env_kernel(b"hello world");
        let src = TaggedPtr::kernel(6);
        assert_eq!(
            read_at(&env, TaggetPtrType::Kernel, src, 5).as_deref(),
            Some(&b"world"[..])
        );
    }

    #[test]
    fn read_at_oob() {
        let env = env_kernel(b"hi");
        let src = TaggedPtr::kernel(0);
        assert!(read_at(&env, TaggetPtrType::Kernel, src, 10).is_none());
    }

    #[test]
    fn read_at_wrong_space() {
        let env = env_kernel(b"hello");
        let src = TaggedPtr::user(0);
        assert!(read_at(&env, TaggetPtrType::Kernel, src, 5).is_none());
    }

    #[test]
    fn read_at_null() {
        let env = env_kernel(b"hello");
        assert!(read_at(&env, TaggetPtrType::Kernel, 0, 1).is_none());
    }

    #[test]
    fn read_at_user_space() {
        let env = env_user(b"abc");
        let src = TaggedPtr::user(0);
        assert_eq!(
            read_at(&env, TaggetPtrType::User, src, 3).as_deref(),
            Some(&b"abc"[..])
        );
    }

    #[test]
    fn read_str_finds_nul() {
        let env = env_kernel(b"hi\0extra");
        let src = TaggedPtr::kernel(0);
        assert_eq!(
            read_str(&env, TaggetPtrType::Kernel, src, 16).as_deref(),
            Some(&b"hi\0"[..])
        );
    }

    #[test]
    fn read_str_truncates_at_cap() {
        let env = env_kernel(b"hello world");
        let src = TaggedPtr::kernel(0);
        assert_eq!(
            read_str(&env, TaggetPtrType::Kernel, src, 4).as_deref(),
            Some(&b"hel\0"[..])
        );
    }

    #[test]
    fn read_str_no_nul_within_region() {
        let env = env_kernel(b"abc");
        let src = TaggedPtr::kernel(0);
        // cap=8 means up to 7 bytes + NUL; region only has 3, so we get those plus NUL.
        assert_eq!(
            read_str(&env, TaggetPtrType::Kernel, src, 8).as_deref(),
            Some(&b"abc\0"[..])
        );
    }
}
