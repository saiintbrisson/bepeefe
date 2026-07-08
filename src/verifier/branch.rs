//! Decides which arms of a conditional jump are viable and how the compared
//! register refines on each one.

use crate::isa::jmp::*;

use super::{RegisterState, Scalar, ScalarRange};

pub(super) type ExprRange = ScalarRange<u64>;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ExprVal {
    Known(ExprRange),
    Unkown,
    PtrToMapValueOrNull(u16),
}

impl ExprVal {
    fn is_single_val(&self) -> bool {
        match self {
            Self::PtrToMapValueOrNull(_) => true,
            ExprVal::Known(range) => range.min == range.max,
            _ => false,
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct BranchResult {
    pub(super) decision: BranchDecision,
    pub(super) branch_reg: Option<RegisterState>,
    pub(super) fallthrough_reg: Option<RegisterState>,
}

impl BranchResult {
    pub fn both() -> Self {
        Self {
            decision: BranchDecision::Both,
            ..Default::default()
        }
    }

    pub fn skip_branch() -> Self {
        Self {
            decision: BranchDecision::SkipBranch,
            ..Self::default()
        }
    }

    pub fn skip_fallthrough() -> Self {
        Self {
            decision: BranchDecision::SkipFallthrough,
            ..Self::default()
        }
    }
}

/// Which arms of a conditional jump the verifier must walk. `Both` when the
/// compared ranges cannot settle the outcome, the skip variants when the jump
/// is provably taken or not taken.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(test, derive(serde::Deserialize))]
pub enum BranchDecision {
    #[default]
    Both,
    SkipBranch,
    SkipFallthrough,
}

pub(super) fn scalar_reg(r: ExprRange) -> RegisterState {
    RegisterState::Scalar(Scalar::U64(r))
}

/// Decides how the branch will be taken and refines the registers.
///
/// * SRC=Unknown: both branches are taken, no refinement done
/// * DST=Unknown, SRC=Known: creates a range for DST and refines using SRC
/// * SRC=DST if they represent a single value:
///   * If JEQ, JGE, JSGE, JLE, JSLE: skip fallthrough
///   * If JNE, JGT, JSGT, JLT, JSLT: skip branch
/// * DST=[`ExprVal::PtrToMapValueOrNull`], SRC=Known:
///   * If JEQ and SRC does not contain NULL: refine to
///     [`RegisterState::PtrToMapValue`] on branch
///   * If JEQ and SRC is NULL: refine to [`RegisterState::PtrToMapValue`] on
///     fallthrough
///   * If JNE and SRC is NULL: refine to [`RegisterState::PtrToMapValue`] on
///     branch
/// * DST=Known, SRC=Known (range-vs-range refinement):
///   * JEQ: skip branch if no overlap. Branch narrows DST to the intersection
///     with SRC. If SRC is a single value, fallthrough excludes it from DST's
///     boundary.
///   * JNE: skip fallthrough if no overlap. Fallthrough narrows DST to the
///     intersection. If SRC is a single value, branch excludes it from DST's
///     boundary.
///   * JGT: branch narrows DST.min up to SRC.min+1, fallthrough narrows DST.max
///     down to SRC.max. Skip branch if DST.max <= SRC.min, skip fallthrough if
///     DST.min > SRC.max. Unsigned comparison.
///   * JSGT: same logic but using signed (i64) arithmetic. When the resulting
///     range can't be stored as a valid unsigned range (min > max), we skip the
///     refinement for that path.
pub(super) fn decide_branch(
    op: u8,
    lhs: ExprVal,
    rhs: ExprVal,
    jmp32: bool,
) -> Result<BranchResult, &'static str> {
    let signed = matches!(op, BPF_JSGT | BPF_JSGE | BPF_JSLT | BPF_JSLE);

    let (dst, src) = match (lhs, rhs) {
        (_, ExprVal::Unkown) => return Ok(BranchResult::default()),

        (ExprVal::Unkown, ExprVal::Known(b)) => {
            let range = match (signed, jmp32) {
                (false, true) => ExprRange {
                    min: 0,
                    max: u32::MAX as u64,
                    stride: 1,
                },
                (false, false) => ExprRange {
                    min: 0,
                    max: u64::MAX,
                    stride: 1,
                },
                (true, true) => ExprRange {
                    min: i32::MIN as i64 as u64,
                    max: i32::MAX as i64 as u64,
                    stride: 1,
                },
                (true, false) => ExprRange {
                    min: i64::MIN as u64,
                    max: i64::MAX as u64,
                    stride: 1,
                },
            };
            (range, b)
        }

        (lhs, rhs) if lhs.is_single_val() && lhs == rhs => {
            return Ok(match op {
                BPF_JEQ | BPF_JGE | BPF_JSGE | BPF_JLE | BPF_JSLE => {
                    BranchResult::skip_fallthrough()
                }
                BPF_JNE | BPF_JGT | BPF_JSGT | BPF_JLT | BPF_JSLT => BranchResult::skip_branch(),
                BPF_JSET => return Err("BPF_JSET refinement is not supported"),
                _ => BranchResult::default(),
            });
        }

        // TODO: prove for JGE, JLE, JGT, JLT
        (ExprVal::PtrToMapValueOrNull(fd), ExprVal::Known(val)) => {
            let mut result = BranchResult::default();
            let register_state = Some(RegisterState::PtrToMapValue {
                map_fd: fd,
                offset: ScalarRange::exact(0),
            });

            match op {
                BPF_JEQ if val.single_val() == Some(0) => result.fallthrough_reg = register_state,
                BPF_JEQ if !val.contains(0) => result.branch_reg = register_state,
                BPF_JNE if val.single_val() == Some(0) => result.branch_reg = register_state,
                _ => {}
            }

            return Ok(result);
        }

        (ExprVal::Known(a), ExprVal::Known(b)) => (a, b),

        (ExprVal::Known(_), ExprVal::PtrToMapValueOrNull(_))
        | (ExprVal::Unkown, ExprVal::PtrToMapValueOrNull(_))
        | (ExprVal::PtrToMapValueOrNull(_), ExprVal::PtrToMapValueOrNull(_)) => {
            return Err("comparison against PtrToMapValueOrNull on this side is not supported");
        }
    };

    let mut result = BranchResult::default();

    match op {
        BPF_JEQ => {
            if !dst.overlap(&src) {
                return Ok(BranchResult::skip_branch());
            }
            // Branch: dst must equal src, so narrow to intersection
            let min = dst.min.max(src.min);
            let max = dst.max.min(src.max);
            let intersection = ExprRange {
                min,
                max,
                stride: if min == max { 1 } else { dst.stride },
            };
            result.branch_reg = Some(scalar_reg(intersection));
            // Fallthrough: dst != src. We can only exclude a boundary
            // point; interior holes can't be represented.
            if let Some(src_val) = src.single_val() {
                match dst.exclude(src_val) {
                    Some(r) => result.fallthrough_reg = Some(scalar_reg(r)),
                    None => result.decision = BranchDecision::SkipFallthrough,
                }
            }
        }
        BPF_JNE => {
            if !dst.overlap(&src) {
                return Ok(BranchResult::skip_fallthrough());
            }
            // Fallthrough: dst == src, so narrow to intersection
            let min = dst.min.max(src.min);
            let max = dst.max.min(src.max);
            let intersection = ExprRange {
                min,
                max,
                stride: if min == max { 1 } else { dst.stride },
            };
            result.fallthrough_reg = Some(scalar_reg(intersection));
            // Branch: dst != src. Exclude boundary point if possible.
            if let Some(src_val) = src.single_val() {
                match dst.exclude(src_val) {
                    Some(r) => result.branch_reg = Some(scalar_reg(r)),
                    None => result.decision = BranchDecision::SkipBranch,
                }
            }
        }
        BPF_JGT => {
            if src.min >= dst.max {
                result.decision = BranchDecision::SkipBranch;
            } else {
                result.branch_reg = Some(scalar_reg(ExprRange {
                    min: (src.min + 1).max(dst.min),
                    max: dst.max,
                    stride: dst.stride,
                }));
            }

            if src.max < dst.min {
                result.decision = BranchDecision::SkipFallthrough;
            } else {
                result.fallthrough_reg = Some(scalar_reg(ExprRange {
                    min: dst.min,
                    max: src.max.min(dst.max),
                    stride: dst.stride,
                }));
            }
        }
        BPF_JSGT => {
            let dst_smin = dst.min as i64;
            let dst_smax = dst.max as i64;
            let src_smin = src.min as i64;
            let src_smax = src.max as i64;

            if src_smin >= dst_smax {
                result.decision = BranchDecision::SkipBranch;
            } else {
                let smin = (src_smin + 1).max(dst_smin);
                let smax = dst_smax;
                if smin <= smax {
                    result.branch_reg = Some(scalar_reg(ExprRange {
                        min: smin as u64,
                        max: smax as u64,
                        stride: dst.stride,
                    }));
                }
            }

            if src_smax < dst_smin {
                result.decision = BranchDecision::SkipFallthrough;
            } else {
                let smin = dst_smin;
                let smax = src_smax.min(dst_smax);
                if smin <= smax {
                    result.fallthrough_reg = Some(scalar_reg(ExprRange {
                        min: smin as u64,
                        max: smax as u64,
                        stride: dst.stride,
                    }));
                }
            }
        }
        _ => {}
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn er(min: u64, max: u64, stride: u64) -> ExprRange {
        ExprRange { min, max, stride }
    }

    fn db32(op: u8, lhs: ExprVal, rhs: ExprVal) -> BranchResult {
        decide_branch(op, lhs, rhs, true).expect("decide_branch unsupported case in test")
    }

    #[test]
    fn decide_branch_known_known() {
        use BranchDecision::*;

        let neg1 = -1i32 as u32 as u64;
        let neg5 = -5i32 as u32 as u64;
        let neg10 = -10i32 as u32 as u64;

        let cases: &[(u8, (u64, u64, u64), (u64, u64, u64), BranchDecision)] = &[
            (BPF_JEQ, (1, 1, 1), (1, 1, 1), SkipFallthrough),
            (BPF_JNE, (1, 1, 1), (1, 1, 1), SkipBranch),
            (BPF_JEQ, (0, 64, 4), (0, 64, 4), Both),
            (BPF_JEQ, (0, 32, 2), (32, 64, 4), Both),
            (BPF_JEQ, (0, 31, 2), (32, 64, 4), SkipBranch),
            (BPF_JNE, (0, 31, 2), (32, 64, 4), SkipFallthrough),
            // -1i32 as u32 == -1i32 as u32
            (BPF_JEQ, (neg1, neg1, 1), (neg1, neg1, 1), SkipFallthrough),
            // [-10..-1] vs [-5..-1]: overlapping
            (BPF_JEQ, (neg10, neg1, 1), (neg5, neg1, 1), Both),
            // [0..10] vs [-5..-1]: no overlap (unsigned: 0..10 vs 0xFFFFFFFB..0xFFFFFFFF)
            (BPF_JEQ, (0, 10, 1), (neg5, neg1, 1), SkipBranch),
            (BPF_JNE, (0, 10, 1), (neg5, neg1, 1), SkipFallthrough),
        ];

        for (op, lhs, rhs, expected) in cases {
            let result = db32(
                *op,
                ExprVal::Known(er(lhs.0, lhs.1, lhs.2)),
                ExprVal::Known(er(rhs.0, rhs.1, rhs.2)),
            );
            assert_eq!(result.decision, *expected, "{op:#x} {lhs:?} vs {rhs:?}");
        }
    }

    #[test]
    fn decide_branch_map_null() {
        let non_null = Some(RegisterState::PtrToMapValue {
            map_fd: 0,
            offset: ScalarRange::exact(0),
        });

        let cases: &[(
            u8,
            (u64, u64, u64),
            Option<RegisterState>,
            Option<RegisterState>,
        )] = &[
            // if equal to 0, ptr is null on branch, fallthrough is non-null
            (BPF_JEQ, (0, 0, 1), None, non_null),
            // can't prove it will be non-null on fallthrough, but ptr can't be 0 on branch
            (BPF_JEQ, (1, 5, 1), non_null, None),
            // range including 0, can't prove anything
            (BPF_JEQ, (0, 5, 1), None, None),
            // if not equal to 0, ptr is non-null on branch
            (BPF_JNE, (0, 0, 1), non_null, None),
            // range including 0, can't prove anything
            (BPF_JNE, (0, 5, 1), None, None),
        ];

        for (op, rhs, exp_branch, exp_ft) in cases {
            let result = db32(
                *op,
                ExprVal::PtrToMapValueOrNull(0),
                ExprVal::Known(er(rhs.0, rhs.1, rhs.2)),
            );
            assert_eq!(result.branch_reg, *exp_branch, "{op:#x} {rhs:?} branch_reg");
            assert_eq!(
                result.fallthrough_reg, *exp_ft,
                "{op:#x} {rhs:?} fallthrough_reg"
            );
        }
    }

    #[test]
    fn decide_branch_jeq_refinement() {
        use BranchDecision::*;

        let sr = |min, max, stride| Some(scalar_reg(er(min, max, stride)));

        // range [2..8, stride 2] JEQ 2, branch gets exact 2, fallthrough gets [4..8]
        let r = db32(
            BPF_JEQ,
            ExprVal::Known(er(2, 8, 2)),
            ExprVal::Known(er(2, 2, 1)),
        );
        assert_eq!(r.decision, Both);
        assert_eq!(r.branch_reg, sr(2, 2, 1));
        assert_eq!(r.fallthrough_reg, sr(4, 8, 2));

        // range [2..8, stride 2] JEQ 8, branch gets exact 8, fallthrough gets [2..6]
        let r = db32(
            BPF_JEQ,
            ExprVal::Known(er(2, 8, 2)),
            ExprVal::Known(er(8, 8, 1)),
        );
        assert_eq!(r.branch_reg, sr(8, 8, 1));
        assert_eq!(r.fallthrough_reg, sr(2, 6, 2));

        // range [5..5] JEQ 5, branch always taken
        let r = db32(
            BPF_JEQ,
            ExprVal::Known(er(5, 5, 1)),
            ExprVal::Known(er(5, 5, 1)),
        );
        assert_eq!(r.decision, SkipFallthrough);

        // range [2..8] JEQ 99, branch never taken
        let r = db32(
            BPF_JEQ,
            ExprVal::Known(er(2, 8, 1)),
            ExprVal::Known(er(99, 99, 1)),
        );
        assert_eq!(r.decision, SkipBranch);

        let neg1 = -1i32 as u32 as u64;
        let neg5 = -5i32 as u32 as u64;
        let neg10 = -10i32 as u32 as u64;

        // [-10..-1] JEQ -1: branch exact -1, fallthrough [-10..-2]
        let r = db32(
            BPF_JEQ,
            ExprVal::Known(er(neg10, neg1, 1)),
            ExprVal::Known(er(neg1, neg1, 1)),
        );
        assert_eq!(r.decision, Both);
        assert_eq!(r.branch_reg, sr(neg1, neg1, 1));
        assert_eq!(r.fallthrough_reg, sr(neg10, neg1 - 1, 1));

        // [-10..-1] JEQ -10: branch exact -10, fallthrough [-9..-1]
        let r = db32(
            BPF_JEQ,
            ExprVal::Known(er(neg10, neg1, 1)),
            ExprVal::Known(er(neg10, neg10, 1)),
        );
        assert_eq!(r.decision, Both);
        assert_eq!(r.branch_reg, sr(neg10, neg10, 1));
        assert_eq!(r.fallthrough_reg, sr(neg10 + 1, neg1, 1));

        // [-5..-1] JNE -5: fallthrough exact -5, branch [-4..-1]
        let r = db32(
            BPF_JNE,
            ExprVal::Known(er(neg5, neg1, 1)),
            ExprVal::Known(er(neg5, neg5, 1)),
        );
        assert_eq!(r.decision, Both);
        assert_eq!(r.fallthrough_reg, sr(neg5, neg5, 1));
        assert_eq!(r.branch_reg, sr(neg5 + 1, neg1, 1));
    }

    #[test]
    fn decide_branch_jgt_refinement() {
        use BranchDecision::*;

        let sr = |min, max, stride| Some(scalar_reg(er(min, max, stride)));

        // range [0..10] JGT 5, branch [6..10], fallthrough [0..5]
        let r = db32(
            BPF_JGT,
            ExprVal::Known(er(0, 10, 1)),
            ExprVal::Known(er(5, 5, 1)),
        );
        assert_eq!(r.decision, Both);
        assert_eq!(r.branch_reg, sr(6, 10, 1));
        assert_eq!(r.fallthrough_reg, sr(0, 5, 1));

        // range [0..5] JGT 10, branch impossible
        let r = db32(
            BPF_JGT,
            ExprVal::Known(er(0, 5, 1)),
            ExprVal::Known(er(10, 10, 1)),
        );
        assert_eq!(r.decision, SkipBranch);

        // range [10..20] JGT 5, fallthrough impossible
        let r = db32(
            BPF_JGT,
            ExprVal::Known(er(10, 20, 1)),
            ExprVal::Known(er(5, 5, 1)),
        );
        assert_eq!(r.decision, SkipFallthrough);

        // [0..20] JGT [3..7]: branch min = 3+1=4, fallthrough max = 7
        let r = db32(
            BPF_JGT,
            ExprVal::Known(er(0, 20, 1)),
            ExprVal::Known(er(3, 7, 1)),
        );
        assert_eq!(r.decision, Both);
        assert_eq!(r.branch_reg, sr(4, 20, 1));
        assert_eq!(r.fallthrough_reg, sr(0, 7, 1));

        // [0..5] JGT [5..10]: dst.max(5) <= src.min(5), branch impossible
        let r = db32(
            BPF_JGT,
            ExprVal::Known(er(0, 5, 1)),
            ExprVal::Known(er(5, 10, 1)),
        );
        assert_eq!(r.decision, SkipBranch);

        // [10..20] JGT [0..5]: dst.min(10) > src.max(5), fallthrough impossible
        let r = db32(
            BPF_JGT,
            ExprVal::Known(er(10, 20, 1)),
            ExprVal::Known(er(0, 5, 1)),
        );
        assert_eq!(r.decision, SkipFallthrough);

        // [0..10] JGT [0..10]: overlapping, both paths possible
        // branch min = 0+1=1, fallthrough max = 10
        let r = db32(
            BPF_JGT,
            ExprVal::Known(er(0, 10, 1)),
            ExprVal::Known(er(0, 10, 1)),
        );
        assert_eq!(r.decision, Both);
        assert_eq!(r.branch_reg, sr(1, 10, 1));
        assert_eq!(r.fallthrough_reg, sr(0, 10, 1));
    }

    #[test]
    fn decide_branch_unknown_refinement() {
        use BranchDecision::*;

        let max = u32::MAX as u64;
        let sr = |min, max, stride| Some(scalar_reg(er(min, max, stride)));

        // Unknown JEQ 0: branch gets exact 0, fallthrough gets [1..MAX]
        let r = db32(BPF_JEQ, ExprVal::Unkown, ExprVal::Known(er(0, 0, 1)));
        assert_eq!(r.decision, Both);
        assert_eq!(r.branch_reg, sr(0, 0, 1));
        assert_eq!(r.fallthrough_reg, sr(1, max, 1));

        // Unknown JEQ 42: branch gets exact 42, fallthrough unchanged (interior)
        let r = db32(BPF_JEQ, ExprVal::Unkown, ExprVal::Known(er(42, 42, 1)));
        assert_eq!(r.decision, Both);
        assert_eq!(r.branch_reg, sr(42, 42, 1));
        assert_eq!(r.fallthrough_reg, sr(0, max, 1));

        // Unknown JNE 0: fallthrough gets exact 0, branch gets [1..MAX]
        let r = db32(BPF_JNE, ExprVal::Unkown, ExprVal::Known(er(0, 0, 1)));
        assert_eq!(r.decision, Both);
        assert_eq!(r.fallthrough_reg, sr(0, 0, 1));
        assert_eq!(r.branch_reg, sr(1, max, 1));

        // Unknown JGT 5: branch gets [6..MAX], fallthrough gets [0..5]
        let r = db32(BPF_JGT, ExprVal::Unkown, ExprVal::Known(er(5, 5, 1)));
        assert_eq!(r.decision, Both);
        assert_eq!(r.branch_reg, sr(6, max, 1));
        assert_eq!(r.fallthrough_reg, sr(0, 5, 1));

        // Unknown JSGT 5: signed, so unknown is [i32::MIN..i32::MAX]
        // branch gets [6..i32::MAX], fallthrough gets [i32::MIN..5]
        let smin = i32::MIN as i64 as u64;
        let smax = i32::MAX as i64 as u64;
        let r = db32(BPF_JSGT, ExprVal::Unkown, ExprVal::Known(er(5, 5, 1)));
        assert_eq!(r.decision, Both);
        assert_eq!(r.branch_reg, sr(6, smax, 1));
        assert_eq!(r.fallthrough_reg, sr(smin, 5, 1));
    }

    #[test]
    fn decide_branch_jsgt_refinement() {
        use BranchDecision::*;

        let sr = |min, max, stride| Some(scalar_reg(er(min, max, stride)));
        let s = |v: i32| v as i64 as u64;

        // [-10..10] JSGT 5: branch [6..10], fallthrough [-10..5]
        let r = db32(
            BPF_JSGT,
            ExprVal::Known(er(s(-10), 10, 1)),
            ExprVal::Known(er(5, 5, 1)),
        );
        assert_eq!(r.decision, Both);
        assert_eq!(r.branch_reg, sr(6, 10, 1));
        assert_eq!(r.fallthrough_reg, sr(s(-10), 5, 1));

        // [-10..-1] JSGT -5: branch [-4..-1], fallthrough [-10..-5]
        let r = db32(
            BPF_JSGT,
            ExprVal::Known(er(s(-10), s(-1), 1)),
            ExprVal::Known(er(s(-5), s(-5), 1)),
        );
        assert_eq!(r.decision, Both);
        assert_eq!(r.branch_reg, sr(s(-4), s(-1), 1));
        assert_eq!(r.fallthrough_reg, sr(s(-10), s(-5), 1));

        // [-5..-1] JSGT 0: all negative < 0, branch impossible
        let r = db32(
            BPF_JSGT,
            ExprVal::Known(er(s(-5), s(-1), 1)),
            ExprVal::Known(er(0, 0, 1)),
        );
        assert_eq!(r.decision, SkipBranch);

        // [5..10] JSGT 0: all > 0, fallthrough impossible
        let r = db32(
            BPF_JSGT,
            ExprVal::Known(er(5, 10, 1)),
            ExprVal::Known(er(0, 0, 1)),
        );
        assert_eq!(r.decision, SkipFallthrough);

        // [-10..10] JSGT [-5..5]: range vs range
        // branch min = -5+1 = -4, clamped to dst_min(-10) -> -4; max = 10
        // fallthrough min = -10; max = min(5, 10) = 5
        let r = db32(
            BPF_JSGT,
            ExprVal::Known(er(s(-10), 10, 1)),
            ExprVal::Known(er(s(-5), 5, 1)),
        );
        assert_eq!(r.decision, Both);
        assert_eq!(r.branch_reg, sr(s(-4), 10, 1));
        assert_eq!(r.fallthrough_reg, sr(s(-10), 5, 1));

        // [5..5] JSGT [5..5]: equal, signed gt is strict, branch impossible
        let r = db32(
            BPF_JSGT,
            ExprVal::Known(er(5, 5, 1)),
            ExprVal::Known(er(5, 5, 1)),
        );
        assert_eq!(r.decision, SkipBranch);
    }
}
