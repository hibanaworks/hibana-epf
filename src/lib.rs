#![cfg_attr(not(feature = "std"), no_std)]

pub mod control_kinds;
pub mod host;
pub mod loader;
pub mod ops;
mod slot_contract;
pub mod verifier;
pub mod vm;

use crate::control_kinds::{
    PolicyActivateKind, PolicyAnnotateKind, PolicyLoadKind, PolicyRevertKind,
};
use hibana::substrate::{
    cap::{ControlResourceKind, GenericCapToken},
    ids::{Lane, RendezvousId, SessionId},
    policy::signals::{ContextId, ContextValue, PolicyAttrs, core as policy_core},
    program::{RoleProgram, project},
    tap::TapEvent,
};
pub use host::{HostSlots, ScratchLease};
pub use verifier::Header;
use vm::Slot;
pub use vm::{Trap, VmCtx};

pub const ROLE_CONTROLLER: u8 = 0;

/// ```compile_fail
/// use hibana::g;
/// use hibana_epf::control_kinds::PolicyLoadKind;
///
/// let _ = g::send::<
///     g::Role<0>,
///     g::Role<1>,
///     g::Msg<{ <PolicyLoadKind as hibana::substrate::cap::ControlResourceKind>::LABEL }, u32>,
///     0,
/// >();
/// ```
///
/// EPF lifecycle controls must use `GenericCapToken<K>` and the control kind as the
/// third message parameter. The old raw label/payload path is forbidden.
type PolicyLoadControlMsg = hibana::g::Msg<
    { <PolicyLoadKind as ControlResourceKind>::LABEL },
    GenericCapToken<PolicyLoadKind>,
    PolicyLoadKind,
>;
type PolicyActivateControlMsg = hibana::g::Msg<
    { <PolicyActivateKind as ControlResourceKind>::LABEL },
    GenericCapToken<PolicyActivateKind>,
    PolicyActivateKind,
>;
type PolicyRevertControlMsg = hibana::g::Msg<
    { <PolicyRevertKind as ControlResourceKind>::LABEL },
    GenericCapToken<PolicyRevertKind>,
    PolicyRevertKind,
>;
type PolicyAnnotateControlMsg = hibana::g::Msg<
    { <PolicyAnnotateKind as ControlResourceKind>::LABEL },
    GenericCapToken<PolicyAnnotateKind>,
    PolicyAnnotateKind,
>;

pub fn attach_controller<'r, 'cfg, T, U, C, const MAX_RV: usize>(
    kit: &'r hibana::substrate::SessionKit<'cfg, T, U, C, MAX_RV>,
    rv: RendezvousId,
    sid: SessionId,
) -> Result<hibana::Endpoint<'r, ROLE_CONTROLLER>, hibana::substrate::AttachError>
where
    T: hibana::substrate::Transport + 'cfg,
    U: hibana::substrate::runtime::LabelUniverse + 'cfg,
    C: hibana::substrate::runtime::Clock + 'cfg,
    'cfg: 'r,
{
    let load = hibana::g::send::<
        hibana::g::Role<ROLE_CONTROLLER>,
        hibana::g::Role<ROLE_CONTROLLER>,
        PolicyLoadControlMsg,
        0,
    >();
    let activate = hibana::g::send::<
        hibana::g::Role<ROLE_CONTROLLER>,
        hibana::g::Role<ROLE_CONTROLLER>,
        PolicyActivateControlMsg,
        0,
    >();
    let revert = hibana::g::send::<
        hibana::g::Role<ROLE_CONTROLLER>,
        hibana::g::Role<ROLE_CONTROLLER>,
        PolicyRevertControlMsg,
        0,
    >();
    let annotate = hibana::g::send::<
        hibana::g::Role<ROLE_CONTROLLER>,
        hibana::g::Role<ROLE_CONTROLLER>,
        PolicyAnnotateControlMsg,
        0,
    >();
    let program = hibana::g::seq(
        load,
        hibana::g::seq(activate, hibana::g::seq(revert, annotate)),
    );
    let projected: RoleProgram<ROLE_CONTROLLER> = project(&program);

    kit.enter(rv, sid, &projected, hibana::substrate::binding::NoBinding)
}

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
pub fn hash_transport_attrs(attrs: &PolicyAttrs) -> u32 {
    let mut hash = FNV32_OFFSET;
    hash = fnv32_mix_opt_u64(
        hash,
        attrs.get(policy_core::LATENCY_US).map(ContextValue::as_u64),
    );
    hash = fnv32_mix_opt_u32(
        hash,
        attrs
            .get(policy_core::QUEUE_DEPTH)
            .map(ContextValue::as_u32),
    );
    hash = fnv32_mix_opt_u64(
        hash,
        attrs
            .get(policy_core::PACING_INTERVAL_US)
            .map(ContextValue::as_u64),
    );
    hash = fnv32_mix_opt_u32(
        hash,
        attrs
            .get(policy_core::CONGESTION_MARKS)
            .map(ContextValue::as_u32),
    );
    hash = fnv32_mix_opt_u32(
        hash,
        attrs
            .get(policy_core::RETRANSMISSIONS)
            .map(ContextValue::as_u32),
    );
    hash = fnv32_mix_opt_u32(
        hash,
        attrs.get(policy_core::PTO_COUNT).map(ContextValue::as_u32),
    );
    hash = fnv32_mix_opt_u64(
        hash,
        attrs.get(policy_core::SRTT_US).map(ContextValue::as_u64),
    );
    hash = fnv32_mix_opt_u64(
        hash,
        attrs
            .get(policy_core::LATEST_ACK_PN)
            .map(ContextValue::as_u64),
    );
    hash = fnv32_mix_opt_u64(
        hash,
        attrs
            .get(policy_core::CONGESTION_WINDOW)
            .map(ContextValue::as_u64),
    );
    hash = fnv32_mix_opt_u64(
        hash,
        attrs
            .get(policy_core::IN_FLIGHT_BYTES)
            .map(ContextValue::as_u64),
    );
    match attrs
        .get(policy_core::TRANSPORT_ALGORITHM)
        .map(ContextValue::as_u32)
    {
        Some(1) => fnv32_mix_u8(hash, 1),
        Some(2) => fnv32_mix_u8(hash, 2),
        Some(raw) if raw >= 0x100 => fnv32_mix_u8(fnv32_mix_u8(hash, 3), (raw - 0x100) as u8),
        Some(raw) => fnv32_mix_u8(fnv32_mix_u8(hash, 3), raw as u8),
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
const fn attr_u32(attrs: &PolicyAttrs, id: ContextId) -> Option<u32> {
    match attrs.get(id) {
        Some(value) => Some(value.as_u32()),
        None => None,
    }
}

#[inline]
const fn attr_u64(attrs: &PolicyAttrs, id: ContextId) -> Option<u64> {
    match attrs.get(id) {
        Some(value) => Some(value.as_u64()),
        None => None,
    }
}

#[inline]
pub const fn replay_transport_inputs(attrs: &PolicyAttrs) -> [u32; 4] {
    [
        saturating_u64_to_u32(attr_u64(attrs, policy_core::LATENCY_US)),
        opt_u32_or_zero(attr_u32(attrs, policy_core::QUEUE_DEPTH)),
        opt_u32_or_zero(attr_u32(attrs, policy_core::CONGESTION_MARKS)),
        opt_u32_or_zero(attr_u32(attrs, policy_core::RETRANSMISSIONS)),
    ]
}

#[inline]
pub const fn replay_transport_presence(attrs: &PolicyAttrs) -> u8 {
    let mut mask = 0u8;
    if attrs.get(policy_core::LATENCY_US).is_some() {
        mask |= 1 << 0;
    }
    if attrs.get(policy_core::QUEUE_DEPTH).is_some() {
        mask |= 1 << 1;
    }
    if attrs.get(policy_core::CONGESTION_MARKS).is_some() {
        mask |= 1 << 2;
    }
    if attrs.get(policy_core::RETRANSMISSIONS).is_some() {
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
fn action_from_vm(vm_action: VmAction) -> Action {
    match vm_action {
        VmAction::Proceed => Action::Proceed,
        VmAction::Abort { reason } => Action::Abort(AbortInfo { reason, trap: None }),
        VmAction::Trap(trap) => Action::Abort(AbortInfo {
            reason: ENGINE_FAIL_CLOSED,
            trap: Some(trap),
        }),
        VmAction::Tap { id, arg0, arg1 } => Action::Tap { id, arg0, arg1 },
        VmAction::Route { arm } if arm <= 1 => Action::Route { arm },
        VmAction::Route { .. } => Action::Abort(AbortInfo {
            reason: ENGINE_FAIL_CLOSED,
            trap: None,
        }),
        VmAction::Defer { retry_hint } => Action::Defer { retry_hint },
    }
}

#[inline]
pub fn run_with<F>(
    host_slots: &HostSlots<'_>,
    slot: Slot,
    event: &TapEvent,
    session: Option<SessionId>,
    lane: Option<Lane>,
    configure: F,
) -> Action
where
    F: FnOnce(&mut VmCtx<'_>),
{
    let vm_action = host_slots.execute_with(slot, event, session, lane, configure);
    action_from_vm(vm_action).with_mode(host_slots.policy_mode(slot))
}
use vm::VmAction;
