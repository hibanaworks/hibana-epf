#![cfg_attr(not(feature = "std"), no_std)]

mod dispatch;
pub mod host;
pub mod loader;
pub mod ops;
mod slot_contract;
pub mod verifier;
pub mod vm;

use hibana::substrate::{
    Lane, SessionId, cap::advanced::CapsMask, tap::TapEvent, transport::TransportSnapshot,
};
pub use host::{HostSlots, ScratchLease};
pub use verifier::Header;
pub use vm::{Slot, Trap, VmCtx};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ScopeTrace {
    pub range: u16,
    pub nest: u16,
}

#[cfg(test)]
impl ScopeTrace {
    const fn pack(self) -> u32 {
        0x8000_0000 | ((self.range as u32) << 16) | self.nest as u32
    }
}

fn tap_scope(event: &TapEvent) -> Option<ScopeTrace> {
    if (event.arg2 & 0x8000_0000) == 0 {
        None
    } else {
        Some(ScopeTrace {
            range: ((event.arg2 & 0x7FFF_0000) >> 16) as u16,
            nest: (event.arg2 & 0x0000_FFFF) as u16,
        })
    }
}

/// Abort outcome emitted by the policy VM (or by the host when mapping traps).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AbortInfo {
    pub reason: u16,
    pub trap: Option<Trap>,
}

/// Engine-level fail-closed reason used when policy execution cannot produce
/// a safe decision.
pub const ENGINE_FAIL_CLOSED: u16 = 0xFFFF;
/// Engine-level liveness exhaustion reason for dynamic route decision loops.
pub const ENGINE_LIVENESS_EXHAUSTED: u16 = 0xFFFE;

/// Runtime policy mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyMode {
    Shadow,
    Enforce,
}

/// Reduced emergency-plane verdict domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyVerdict {
    Proceed,
    RouteArm(u8),
    Reject(u16),
}

#[inline]
pub const fn policy_mode_tag(mode: PolicyMode) -> u8 {
    match mode {
        PolicyMode::Shadow => 0,
        PolicyMode::Enforce => 1,
    }
}

#[inline]
pub const fn verdict_tag(verdict: PolicyVerdict) -> u8 {
    match verdict {
        PolicyVerdict::Proceed => 0,
        PolicyVerdict::RouteArm(_) => 1,
        PolicyVerdict::Reject(_) => 2,
    }
}

#[inline]
pub const fn verdict_arm(verdict: PolicyVerdict) -> u8 {
    match verdict {
        PolicyVerdict::RouteArm(arm) => arm,
        _ => 0,
    }
}

#[inline]
pub const fn verdict_reason(verdict: PolicyVerdict) -> u16 {
    match verdict {
        PolicyVerdict::Reject(reason) => reason,
        _ => 0,
    }
}

#[inline]
pub const fn slot_tag(slot: Slot) -> u8 {
    match slot {
        Slot::Forward => 0,
        Slot::EndpointRx => 1,
        Slot::EndpointTx => 2,
        Slot::Rendezvous => 3,
        Slot::Route => 4,
    }
}

const FNV32_OFFSET: u32 = 0x811C_9DC5;
const FNV32_PRIME: u32 = 0x0100_0193;

#[inline]
fn fnv32_mix_u8(mut hash: u32, byte: u8) -> u32 {
    hash ^= byte as u32;
    hash.wrapping_mul(FNV32_PRIME)
}

#[inline]
fn fnv32_mix_u16(hash: u32, value: u16) -> u32 {
    let bytes = value.to_le_bytes();
    let hash = fnv32_mix_u8(hash, bytes[0]);
    fnv32_mix_u8(hash, bytes[1])
}

#[inline]
fn fnv32_mix_u32(hash: u32, value: u32) -> u32 {
    let bytes = value.to_le_bytes();
    let hash = fnv32_mix_u8(hash, bytes[0]);
    let hash = fnv32_mix_u8(hash, bytes[1]);
    let hash = fnv32_mix_u8(hash, bytes[2]);
    fnv32_mix_u8(hash, bytes[3])
}

#[inline]
fn fnv32_mix_u64(hash: u32, value: u64) -> u32 {
    let bytes = value.to_le_bytes();
    let mut out = hash;
    let mut idx = 0usize;
    while idx < bytes.len() {
        out = fnv32_mix_u8(out, bytes[idx]);
        idx += 1;
    }
    out
}

#[inline]
fn fnv32_mix_opt_u32(hash: u32, value: Option<u32>) -> u32 {
    match value {
        Some(v) => fnv32_mix_u32(fnv32_mix_u8(hash, 1), v),
        None => fnv32_mix_u8(hash, 0),
    }
}

#[inline]
fn fnv32_mix_opt_u64(hash: u32, value: Option<u64>) -> u32 {
    match value {
        Some(v) => fnv32_mix_u64(fnv32_mix_u8(hash, 1), v),
        None => fnv32_mix_u8(hash, 0),
    }
}

#[inline]
pub fn hash_tap_event(event: &TapEvent) -> u32 {
    let mut hash = FNV32_OFFSET;
    hash = fnv32_mix_u32(hash, event.ts);
    hash = fnv32_mix_u16(hash, event.id);
    hash = fnv32_mix_u16(hash, event.causal_key);
    hash = fnv32_mix_u32(hash, event.arg0);
    hash = fnv32_mix_u32(hash, event.arg1);
    fnv32_mix_u32(hash, event.arg2)
}

#[inline]
pub fn hash_policy_input(input: [u32; 4]) -> u32 {
    let mut hash = FNV32_OFFSET;
    let mut idx = 0usize;
    while idx < input.len() {
        hash = fnv32_mix_u32(hash, input[idx]);
        idx += 1;
    }
    hash
}

#[inline]
pub fn hash_transport_snapshot(snapshot: TransportSnapshot) -> u32 {
    let mut hash = FNV32_OFFSET;
    hash = fnv32_mix_opt_u64(hash, snapshot.latency_us);
    hash = fnv32_mix_opt_u32(hash, snapshot.queue_depth);
    hash = fnv32_mix_opt_u64(hash, snapshot.pacing_interval_us);
    hash = fnv32_mix_opt_u32(hash, snapshot.congestion_marks);
    hash = fnv32_mix_opt_u32(hash, snapshot.retransmissions);
    hash = fnv32_mix_opt_u32(hash, snapshot.pto_count);
    hash = fnv32_mix_opt_u64(hash, snapshot.srtt_us);
    hash = fnv32_mix_opt_u64(hash, snapshot.latest_ack_pn);
    hash = fnv32_mix_opt_u64(hash, snapshot.congestion_window);
    hash = fnv32_mix_opt_u64(hash, snapshot.in_flight_bytes);
    match snapshot.algorithm {
        Some(hibana::substrate::transport::TransportAlgorithm::Cubic) => fnv32_mix_u8(hash, 1),
        Some(hibana::substrate::transport::TransportAlgorithm::Reno) => fnv32_mix_u8(hash, 2),
        Some(hibana::substrate::transport::TransportAlgorithm::Other(code)) => {
            fnv32_mix_u8(fnv32_mix_u8(hash, 3), code)
        }
        None => fnv32_mix_u8(hash, 0),
    }
}

#[inline]
const fn saturating_u64_to_u32(value: Option<u64>) -> u32 {
    match value {
        Some(v) => {
            if v > u32::MAX as u64 {
                u32::MAX
            } else {
                v as u32
            }
        }
        None => 0,
    }
}

#[inline]
const fn opt_u32_or_zero(value: Option<u32>) -> u32 {
    match value {
        Some(v) => v,
        None => 0,
    }
}

#[inline]
pub const fn replay_transport_inputs(snapshot: TransportSnapshot) -> [u32; 4] {
    [
        saturating_u64_to_u32(snapshot.latency_us),
        opt_u32_or_zero(snapshot.queue_depth),
        opt_u32_or_zero(snapshot.congestion_marks),
        opt_u32_or_zero(snapshot.retransmissions),
    ]
}

#[inline]
pub const fn replay_transport_presence(snapshot: TransportSnapshot) -> u8 {
    let mut mask = 0u8;
    if snapshot.latency_us.is_some() {
        mask |= 1 << 0;
    }
    if snapshot.queue_depth.is_some() {
        mask |= 1 << 1;
    }
    if snapshot.congestion_marks.is_some() {
        mask |= 1 << 2;
    }
    if snapshot.retransmissions.is_some() {
        mask |= 1 << 3;
    }
    mask
}

/// Unified action surface consumed by slot owners.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Proceed,
    Abort(AbortInfo),
    Tap { id: u16, arg0: u32, arg1: u32 },
    Route { arm: u8 },
    Defer { retry_hint: u8 },
}

impl Action {
    #[inline]
    pub const fn verdict(self) -> PolicyVerdict {
        match self {
            Action::Proceed => PolicyVerdict::Proceed,
            Action::Route { arm } if arm <= 1 => PolicyVerdict::RouteArm(arm),
            Action::Route { .. } => PolicyVerdict::Reject(ENGINE_FAIL_CLOSED),
            Action::Abort(info) => PolicyVerdict::Reject(info.reason),
            Action::Tap { .. } => PolicyVerdict::Proceed,
            Action::Defer { .. } => PolicyVerdict::Proceed,
        }
    }

    #[inline]
    pub const fn with_mode(self, mode: PolicyMode) -> Self {
        match mode {
            PolicyMode::Enforce => self,
            PolicyMode::Shadow => match self {
                Action::Tap { .. } => self,
                _ => Action::Proceed,
            },
        }
    }
}

#[inline]
pub fn run_with<F>(
    host_slots: &HostSlots<'_>,
    slot: Slot,
    event: &TapEvent,
    caps: CapsMask,
    session: Option<SessionId>,
    lane: Option<Lane>,
    configure: F,
) -> Action
where
    F: FnOnce(&mut VmCtx<'_>),
{
    let vm_action = host_slots.execute_with(slot, event, caps, session, lane, configure);
    let action = match vm_action {
        VmAction::Proceed => Action::Proceed,
        VmAction::Abort { reason } => Action::Abort(AbortInfo { reason, trap: None }),
        VmAction::Trap(trap) => Action::Abort(AbortInfo {
            reason: ENGINE_FAIL_CLOSED,
            trap: Some(trap),
        }),
        VmAction::Tap { id, arg0, arg1 } => Action::Tap { id, arg0, arg1 },
        VmAction::Route { arm } => Action::Route { arm },
        VmAction::Defer { retry_hint } => Action::Defer { retry_hint },
        VmAction::Ra(_) => Action::Abort(AbortInfo {
            reason: ENGINE_FAIL_CLOSED,
            trap: Some(Trap::IllegalSyscall),
        }),
    };
    action.with_mode(host_slots.policy_mode(slot))
}
use vm::VmAction;
