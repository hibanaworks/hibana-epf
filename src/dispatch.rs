use hibana::substrate::cap::advanced::ControlOp;

use crate::vm::Slot;
use crate::{OpSet, ops};

/// Rendezvous control operations surfaced by the VM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RaOp {
    SpliceBegin { arg: u32 },
    SpliceCommit { arg: u32 },
    SpliceAbort { arg: u32 },
    Checkpoint,
    Rollback { generation: u32 },
}

impl RaOp {
    #[inline]
    const fn required_op(self) -> ControlOp {
        match self {
            RaOp::SpliceBegin { .. } => ControlOp::TopologyBegin,
            RaOp::SpliceCommit { .. } => ControlOp::TopologyCommit,
            RaOp::SpliceAbort { .. } => ControlOp::AbortBegin,
            RaOp::Checkpoint => ControlOp::StateSnapshot,
            RaOp::Rollback { .. } => ControlOp::StateRestore,
        }
    }
}

/// Errors surfaced by the dispatch layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SyscallError {
    UnknownEffectOpcode(u8),
    NotAuthorised { slot: Slot, opcode: u8 },
}

/// Map the byte-sized effect opcode used in bytecode to a concrete [`RaOp`].
pub(crate) fn decode_effect_call(op: u8, arg: u32) -> Result<RaOp, SyscallError> {
    let ra = match op {
        ops::effect::SPLICE_BEGIN => RaOp::SpliceBegin { arg },
        ops::effect::SPLICE_COMMIT => RaOp::SpliceCommit { arg },
        ops::effect::SPLICE_ABORT => RaOp::SpliceAbort { arg },
        ops::effect::CHECKPOINT => RaOp::Checkpoint,
        ops::effect::ROLLBACK => RaOp::Rollback { generation: arg },
        other => return Err(SyscallError::UnknownEffectOpcode(other)),
    };
    Ok(ra)
}

/// Validate that the requested control-plane effect is permitted for the given slot.
pub(crate) fn ensure_allowed(slot: Slot, caps: OpSet, op: RaOp) -> Result<RaOp, SyscallError> {
    if !matches!(slot, Slot::Rendezvous) || !caps.allows(op.required_op()) {
        return Err(SyscallError::NotAuthorised {
            slot,
            opcode: op.required_op() as u8,
        });
    }
    Ok(op)
}
