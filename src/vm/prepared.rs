use std::{ops::Deref, sync::Arc};

use super::{
    Vm,
    cpu::{Cpu, CtxImage},
    ptr::TaggedPtr,
    task::Task,
};
use crate::{
    Value, btf::BtfKind, capture::Capture, error::RuntimeError, object::EbpfProgram,
    verifier::VerificationOutput,
};

pub struct PreparedProgram {
    pub(super) vm: Arc<Vm>,
    pub(super) prog: Arc<EbpfProgram>,
    pub(super) ctx_size: usize,
    pub(super) max_call_depth: usize,
}

impl PreparedProgram {
    /// Constructed only by `Vm::prepare_inner` after the program has been fully
    /// verified. Context-parameter types come from the BTF the verifier has
    /// already validated, so the size lookups below cannot observe a missing or
    /// unsized type.
    pub(super) fn new(
        vm: Arc<Vm>,
        prog: Arc<EbpfProgram>,
        verification_output: VerificationOutput,
    ) -> Arc<Self> {
        let btf = &prog.btf;
        let total_param_size: u32 = prog
            .func
            .params_types
            .iter()
            .map(|(_, param)| {
                let ty = btf.resolve_must(*param);
                match ty.kind() {
                    BtfKind::Ptr(pointee) => btf.resolve_must(*pointee).size(),
                    _ => ty.size(),
                }
            })
            .sum();
        let ctx_size = total_param_size.next_power_of_two() as usize;

        Arc::new(Self {
            vm,
            prog,
            ctx_size,
            max_call_depth: verification_output.max_call_depth,
        })
    }

    pub fn run(&self, image: CtxImage, capture: Option<Arc<dyn Capture>>) -> u64 {
        let mut state = self.start(image, capture);
        while !state.step() {}
        state.return_val()
    }

    pub fn start(&self, image: CtxImage, capture: Option<Arc<dyn Capture>>) -> Cpu {
        Cpu::new(capture, image)
    }

    /// Given a function name, we search for a matching BTF function entry. The
    /// `ctx_params` are a list of `(field name, value)` used to generate a
    /// function context, the eBPFs proogram parameter, like `__sk_buff`.
    ///
    /// The function uses BTF information to generate the entire struct zeroed,
    /// and each entry in `params` overrides one of the context's fields.
    ///
    /// # Example
    ///
    /// An entrypoint that takes `__sk_buff` can be built with:
    ///
    /// ```no_run
    /// # use bepeefe::{
    /// #     EbpfObject, Value,
    /// #     vm::{MapReuseStrategy, Vm},
    /// #     verifier::VerifierConfig,
    /// # };
    /// # let file = std::fs::read("./c-examples/map_array.o").unwrap();
    /// let obj = EbpfObject::from_elf(&file).unwrap();
    /// let prog = obj.load_prog("entry").unwrap();
    /// let vm = Vm::new();
    /// let prepared = vm
    ///     .prepare(prog, MapReuseStrategy::None, &VerifierConfig::default())
    ///     .unwrap();
    /// let image = prepared
    ///     .build_image(&[Value::from([
    ///         ("local_port", Value::Number(3000)),
    ///         ("len", Value::Number(64)),
    ///     ])])
    ///     .unwrap();
    /// prepared.run(image, None);
    /// ```
    ///
    /// The resulting context will be a zeroed buffer of the size of the
    /// `__sk_buff` struct as described by BTF, populated with the `local_port`
    /// and `len` fields. Any type that implements `serde::Serialize` can be
    /// passed directly.
    pub fn build_image<T: serde::Serialize>(
        self: &Arc<Self>,
        params: &[T],
    ) -> Result<CtxImage, RuntimeError> {
        let btf = &self.prog.btf;
        let param_types = &self.prog.func.params_types;
        if param_types.len() != params.len() {
            return Err(RuntimeError::ContextArity {
                expected: param_types.len(),
                got: params.len(),
            });
        }

        let mut ctx_buf = Vec::with_capacity(self.ctx_size);
        let mut arg_regs = Vec::with_capacity(param_types.len());
        let mut buf_idx = 0usize;

        for (idx, ((_, type_id), val)) in param_types.iter().zip(params).enumerate() {
            let param_ty = btf.resolve_must(*type_id);
            let val = crate::to_value(val)?;
            let reg_idx = (idx + 1) as u8;

            match param_ty.kind() {
                BtfKind::Ptr(pointee) => {
                    let pointee_ty = btf.resolve_must(*pointee);
                    let bytes = val.to_bytes(pointee_ty)?;
                    ctx_buf.extend(&bytes);
                    arg_regs.push((reg_idx, TaggedPtr::local(buf_idx as u32)));
                    buf_idx += bytes.len();
                }
                _ => match val {
                    Value::Number(num) => arg_regs.push((reg_idx, num as u64)),
                    Value::Float(f) => arg_regs.push((reg_idx, f.to_bits())),
                    _ => {}
                },
            }
        }

        ctx_buf.resize(self.ctx_size, 0);

        Ok(CtxImage {
            prog: self.clone(),
            ctx_buf,
            arg_regs,
            task: Task::default(),
        })
    }
}

impl Deref for PreparedProgram {
    type Target = EbpfProgram;

    fn deref(&self) -> &Self::Target {
        self.prog.as_ref()
    }
}
