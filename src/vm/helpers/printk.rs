use std::ffi::CStr;

use super::BpfHelper;
use super::args::{Call, In, Raw};

pub struct TracePrintk;
impl TracePrintk {
    pub const ID: i32 = 6;
}
impl BpfHelper for TracePrintk {
    type Args = (In, Raw, Raw, Raw);

    fn name(&self) -> &'static str {
        "bpf_trace_printk"
    }

    fn exec(&self, cx: &mut Call<'_>, (fmt, a, b, c): Self::Args) -> u64 {
        bpf_trace_printk(cx, &fmt.0, [a.0, b.0, c.0])
    }
}

/// Prepares the formatting string for `printk()` calls.
///
/// This is a very small reproduction of the Kernel's `printk`
/// functionality, currently only supporting two specifiers,
/// `d` and `s`.
///
/// From the kernel:
/// > The conversion specifiers supported by *fmt* are similar, but
/// > more limited than for printk(). They are **%d**, **%i**,
/// > **%u**, **%x**, **%ld**, **%li**, **%lu**, **%lx**, **%lld**,
/// > **%lli**, **%llu**, **%llx**, **%p**, **%s**. No modifier (size
/// > of field, padding with zeroes, etc.) is available, and the
/// > helper will return **-EINVAL** (but print nothing) if it
/// > encounters an unknown specifier.
///
/// Ref: <https://github.com/torvalds/linux/blob/f406055cb18c6e299c4a783fc1effeb16be41803/include/uapi/linux/bpf.h#L1961>
fn bpf_trace_printk(cx: &Call<'_>, data: &[u8], params: [u64; 3]) -> u64 {
    enum FmtState {
        WaitingNext(Option<Vec<u8>>),
        Formatting(Vec<u8>),
    }

    let Ok(s) = CStr::from_bytes_until_nul(data) else {
        return -22i64 as u64;
    };
    let Ok(s) = s.to_str() else {
        return -22i64 as u64;
    };

    let mut arg_count = 0;
    let mut utf8_buf = [0u8; 4];
    let mut fmt_state = FmtState::WaitingNext(None);

    for (idx, c) in s.char_indices() {
        if let FmtState::Formatting(mut buf) = fmt_state {
            arg_count += 1;
            if arg_count >= 4 {
                return -22i64 as u64;
            }

            let Some(&param) = params.get(arg_count - 1) else {
                return -22i64 as u64;
            };
            match c {
                'd' => {
                    buf.extend(param.to_string().as_bytes());
                }
                's' => {
                    let data = cx.local_tail(param).unwrap_or(&[0]);
                    let Ok(s) = CStr::from_bytes_until_nul(data) else {
                        return -22i64 as u64;
                    };
                    buf.extend(s.to_bytes());
                }
                // TODO: support for other formats
                _ => return -22i64 as u64,
            }

            fmt_state = FmtState::WaitingNext(Some(buf));
        } else if c == '%' {
            match fmt_state {
                FmtState::WaitingNext(buf) => {
                    fmt_state = FmtState::Formatting(buf.unwrap_or_else(|| {
                        let mut items = Vec::with_capacity(s.len());
                        #[expect(
                            clippy::indexing_slicing,
                            reason = "idx is a byte index produced by char_indices() over s, \
                                      so it always lies on a UTF-8 boundary within s.as_bytes()"
                        )]
                        items.extend_from_slice(&s.as_bytes()[..idx]);
                        items
                    }));
                }
                FmtState::Formatting(_) => return -22i64 as u64,
            }
        } else if let FmtState::WaitingNext(Some(buf)) = &mut fmt_state {
            let s = c.encode_utf8(&mut utf8_buf[..]);
            buf.extend(s.as_bytes());
        }
    }

    let s: std::borrow::Cow<'_, _> = if let FmtState::WaitingNext(Some(buf)) = fmt_state {
        if let Ok(s) = String::from_utf8(buf) {
            s.into()
        } else {
            return -22i64 as u64;
        }
    } else {
        s.into()
    };

    let len = s.len() as u64;

    if let Some(capture) = cx.capture() {
        capture.record(crate::capture::Event::Print(s));
    }

    len
}
