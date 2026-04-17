use hibana::substrate::cap::advanced::CapsMask;

use crate::ops;
use crate::vm::Slot;

const CP_EFFECT_SPLICE_BEGIN_BIT: u16 = 1 << 1;
const CP_EFFECT_SPLICE_COMMIT_BIT: u16 = 1 << 3;
const CP_EFFECT_ABORT_BIT: u16 = 1 << 9;
const CP_EFFECT_CHECKPOINT_BIT: u16 = 1 << 10;
const CP_EFFECT_ROLLBACK_BIT: u16 = 1 << 11;

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
    const fn required_bit(self) -> u16 {
        match self {
            RaOp::SpliceBegin { .. } => CP_EFFECT_SPLICE_BEGIN_BIT,
            RaOp::SpliceCommit { .. } => CP_EFFECT_SPLICE_COMMIT_BIT,
            RaOp::SpliceAbort { .. } => CP_EFFECT_ABORT_BIT,
            RaOp::Checkpoint => CP_EFFECT_CHECKPOINT_BIT,
            RaOp::Rollback { .. } => CP_EFFECT_ROLLBACK_BIT,
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
pub(crate) fn ensure_allowed(slot: Slot, caps: CapsMask, op: RaOp) -> Result<RaOp, SyscallError> {
    if !matches!(slot, Slot::Rendezvous) || (caps.bits() & op.required_bit()) == 0 {
        return Err(SyscallError::NotAuthorised {
            slot,
            opcode: op.required_bit().trailing_zeros() as u8,
        });
    }
    Ok(op)
}
