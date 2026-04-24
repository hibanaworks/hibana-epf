//! Host integration for executing EPF VM policies without global state.

use core::{array, cell::Cell, marker::PhantomData, ptr::NonNull};

use hibana::substrate::{Lane, SessionId, tap::TapEvent};

use super::{
    PolicyMode,
    verifier::{Header, VerifiedImage, VerifyError},
    vm::{Slot, Vm, VmAction, VmCtx},
};

const SLOT_COUNT: usize = 5;

#[inline]
const fn slot_index(slot: Slot) -> usize {
    match slot {
        Slot::Forward => 0,
        Slot::EndpointRx => 1,
        Slot::EndpointTx => 2,
        Slot::Rendezvous => 3,
        Slot::Route => 4,
    }
}

/// Errors surfaced by the policy host registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostError {
    SlotOccupied,
    SlotEmpty,
    InvalidFuel,
    ScratchTooSmall { requested: usize, available: usize },
    ScratchTooLarge { provided: usize, max: usize },
    Verify(VerifyError),
}

/// Install failure that preserves the caller-owned scratch lease for retry or
/// rollback.
pub struct InstallError<'arena> {
    error: HostError,
    scratch: ScratchLease<'arena>,
}

impl<'arena> InstallError<'arena> {
    #[inline]
    const fn new(error: HostError, scratch: ScratchLease<'arena>) -> Self {
        Self { error, scratch }
    }

    /// Inspect the host error without consuming the recovered scratch lease.
    #[inline]
    pub const fn error(&self) -> HostError {
        self.error
    }

    /// Recover both the host error and the scratch lease for retry paths.
    #[inline]
    pub fn into_parts(self) -> (HostError, ScratchLease<'arena>) {
        (self.error, self.scratch)
    }

    /// Recover the scratch lease when the precise host error is not needed.
    #[inline]
    pub fn into_scratch(self) -> ScratchLease<'arena> {
        self.scratch
    }
}

impl core::fmt::Debug for InstallError<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InstallError")
            .field("error", &self.error)
            .field("scratch", &self.scratch)
            .finish()
    }
}

/// Exclusive scratch-memory lease held by an installed slot.
pub struct ScratchLease<'arena> {
    ptr: NonNull<u8>,
    len: usize,
    _borrow: PhantomData<&'arena mut [u8]>,
}

impl<'arena> ScratchLease<'arena> {
    /// Wrap caller-owned scratch memory so it can be moved into `HostSlots`.
    pub fn new(scratch: &'arena mut [u8]) -> Self {
        let ptr = NonNull::new(scratch.as_mut_ptr()).unwrap_or_else(NonNull::dangling);
        Self {
            ptr,
            len: scratch.len(),
            _borrow: PhantomData,
        }
    }

    /// Recover the borrowed scratch memory after uninstall.
    pub fn into_inner(self) -> &'arena mut [u8] {
        let ptr = self.ptr;
        let len = self.len;
        // Prevent Drop from observing partially-moved state if this type ever gains one.
        core::mem::forget(self);
        unsafe { core::slice::from_raw_parts_mut(ptr.as_ptr(), len) }
    }

    #[inline]
    const fn len(&self) -> usize {
        self.len
    }

    #[inline]
    unsafe fn as_mem_slice(&self, used: usize) -> &mut [u8] {
        debug_assert!(used <= self.len);
        unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), used) }
    }
}

impl core::fmt::Debug for ScratchLease<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ScratchLease")
            .field("len", &self.len)
            .finish()
    }
}

/// Registered policy machine (bytecode + scratch + fuel budget).
struct Machine<'arena> {
    code_len: usize,
    code: [u8; VerifiedImage::MAX_CODE_LEN],
    mem_len: usize,
    fuel_max: u16,
    digest: u32,
    scratch: ScratchLease<'arena>,
}

impl<'arena> Machine<'arena> {
    fn from_verified<'code>(
        slot: Slot,
        verified: VerifiedImage<'code>,
        scratch: ScratchLease<'arena>,
    ) -> Result<Self, InstallError<'arena>> {
        let verified = match verified.confirm_slot(slot) {
            Ok(verified) => verified,
            Err(err) => return Err(InstallError::new(HostError::Verify(err), scratch)),
        };
        Self::with_mem(
            verified.code,
            scratch,
            verified.header.mem_len as usize,
            verified.header.fuel_max,
            verified.header.hash,
        )
    }

    fn with_mem(
        code: &[u8],
        scratch: ScratchLease<'arena>,
        mem_len: usize,
        fuel_max: u16,
        digest: u32,
    ) -> Result<Self, InstallError<'arena>> {
        let scratch_len = scratch.len();
        if fuel_max == 0 {
            return Err(InstallError::new(HostError::InvalidFuel, scratch));
        }
        if mem_len > scratch_len {
            return Err(InstallError::new(
                HostError::ScratchTooSmall {
                    requested: mem_len,
                    available: scratch_len,
                },
                scratch,
            ));
        }
        let max_mem = Header::max_mem_len();
        if mem_len > max_mem {
            return Err(InstallError::new(
                HostError::ScratchTooLarge {
                    provided: mem_len,
                    max: max_mem,
                },
                scratch,
            ));
        }
        let code_len = code.len();
        let mut code_storage = [0u8; VerifiedImage::MAX_CODE_LEN];
        code_storage[..code_len].copy_from_slice(code);
        Ok(Self {
            code_len,
            code: code_storage,
            mem_len,
            fuel_max,
            digest,
            scratch,
        })
    }

    #[inline]
    const fn digest(&self) -> u32 {
        self.digest
    }

    fn execute(&self, ctx: &mut VmCtx<'_>) -> (VmAction, u16) {
        let mem_len = self.mem_len;
        let code = &self.code[..self.code_len];
        // SAFETY: `scratch` remains exclusively held by the installed machine.
        let mem_slice = unsafe { self.scratch.as_mem_slice(mem_len) };
        let mut vm = Vm::new(code, mem_slice, self.fuel_max);
        let action = vm.execute(ctx);
        let fuel_used = self.fuel_max.saturating_sub(vm.fuel);
        (action, fuel_used)
    }
}

impl core::fmt::Debug for Machine<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Machine")
            .field("code_len", &self.code_len)
            .field("mem_len", &self.mem_len)
            .field("fuel_max", &self.fuel_max)
            .field("digest", &self.digest)
            .finish()
    }
}

/// In-memory EPF slot registry.
pub struct HostSlots<'arena> {
    machines: [Option<Machine<'arena>>; SLOT_COUNT],
    policy_modes: [Cell<PolicyMode>; SLOT_COUNT],
    active_digests: [Cell<Option<u32>>; SLOT_COUNT],
    last_fuel_used: [Cell<u16>; SLOT_COUNT],
}

impl<'arena> Default for HostSlots<'arena> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'arena> HostSlots<'arena> {
    pub fn new() -> Self {
        Self {
            machines: array::from_fn(|_| None),
            policy_modes: array::from_fn(|_| Cell::new(PolicyMode::Enforce)),
            active_digests: array::from_fn(|_| Cell::new(None)),
            last_fuel_used: array::from_fn(|_| Cell::new(0)),
        }
    }

    pub unsafe fn init_empty(dst: *mut Self) {
        unsafe {
            dst.write(Self::new());
        }
    }

    #[inline]
    fn index(slot: Slot) -> usize {
        slot_index(slot)
    }

    fn install_machine(&mut self, slot: Slot, machine: Machine<'arena>) -> Result<(), HostError> {
        let idx = Self::index(slot);
        if self.machines[idx].is_some() {
            return Err(HostError::SlotOccupied);
        }
        self.active_digests[idx].set(Some(machine.digest()));
        self.machines[idx] = Some(machine);
        Ok(())
    }

    /// Install a verified image into the given slot by copying code into slot-owned
    /// storage and borrowing caller-owned scratch memory for execution.
    pub fn install_verified<'code>(
        &mut self,
        slot: Slot,
        verified: VerifiedImage<'code>,
        scratch: ScratchLease<'arena>,
    ) -> Result<(), InstallError<'arena>> {
        let idx = Self::index(slot);
        if self.machines[idx].is_some() {
            return Err(InstallError::new(HostError::SlotOccupied, scratch));
        }
        let machine = Machine::from_verified(slot, verified, scratch)?;
        match self.install_machine(slot, machine) {
            Ok(()) => Ok(()),
            Err(HostError::SlotOccupied) => unreachable!("slot was prechecked empty"),
            Err(other) => unreachable!("unexpected install_machine error: {other:?}"),
        }
    }

    /// Remove the currently active image from the given slot.
    pub fn uninstall(&mut self, slot: Slot) -> Result<ScratchLease<'arena>, HostError> {
        let idx = Self::index(slot);
        let Some(machine) = self.machines[idx].take() else {
            return Err(HostError::SlotEmpty);
        };
        self.active_digests[idx].set(None);
        self.last_fuel_used[idx].set(0);
        Ok(machine.scratch)
    }

    #[inline]
    pub fn set_policy_mode(&self, slot: Slot, mode: PolicyMode) {
        self.policy_modes[Self::index(slot)].set(mode);
    }

    #[inline]
    pub fn policy_mode(&self, slot: Slot) -> PolicyMode {
        self.policy_modes[Self::index(slot)].get()
    }

    #[inline]
    pub fn active_digest(&self, slot: Slot) -> Option<u32> {
        self.active_digests[Self::index(slot)].get()
    }

    #[inline]
    pub fn last_fuel_used(&self, slot: Slot) -> u16 {
        self.last_fuel_used[Self::index(slot)].get()
    }

    pub(crate) fn execute_with<F>(
        &self,
        slot: Slot,
        event: &TapEvent,
        session: Option<SessionId>,
        lane: Option<Lane>,
        configure: F,
    ) -> VmAction
    where
        F: FnOnce(&mut VmCtx<'_>),
    {
        let mut ctx = VmCtx::new(event);
        if let Some(session) = session {
            ctx.set_session(session);
        }
        if let Some(lane) = lane {
            ctx.set_lane(lane);
        }
        configure(&mut ctx);

        match &self.machines[Self::index(slot)] {
            Some(machine) => {
                let (action, used) = machine.execute(&mut ctx);
                self.last_fuel_used[Self::index(slot)].set(used);
                action
            }
            None => {
                self.last_fuel_used[Self::index(slot)].set(0);
                VmAction::Proceed
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AbortInfo, Action, ops, run_with};
    use hibana::substrate::tap::TapEvent;

    fn setup_machine<'a>(code: &'a [u8], scratch: &'a mut [u8; 64]) -> Machine<'a> {
        let len = scratch.len();
        Machine::with_mem(
            code,
            ScratchLease::new(scratch),
            len,
            8,
            crate::verifier::compute_hash(code),
        )
        .expect("machine")
    }

    #[test]
    fn host_traps_removed_effect_opcode() {
        static CODE: [u8; 3] = [0x30, 0x03, 0x00];
        let mut scratch = [0u8; 64];
        let machine = setup_machine(&CODE, &mut scratch);
        let mut slots = HostSlots::new();
        slots
            .install_machine(Slot::Rendezvous, machine)
            .expect("install");

        static EVENT: TapEvent = TapEvent::zero();
        let result = slots.execute_with(
            Slot::Rendezvous,
            &EVENT,
            Some(SessionId::new(7)),
            Some(Lane::new(3)),
            |_| {},
        );

        assert_eq!(result, VmAction::Trap(crate::vm::Trap::IllegalOpcode(0x30)));
        assert_eq!(
            slots.active_digest(Slot::Rendezvous),
            Some(crate::verifier::compute_hash(&CODE))
        );
        let _ = slots.last_fuel_used(Slot::Rendezvous);
        let _ = slots.uninstall(Slot::Rendezvous).expect("uninstall");
    }

    #[test]
    fn shadow_mode_suppresses_enforcement() {
        static CODE: [u8; 3] = [ops::instr::ACT_ABORT, 0x34, 0x12];
        let mut scratch = [0u8; 64];
        let machine = setup_machine(&CODE, &mut scratch);
        let mut slots = HostSlots::new();
        slots
            .install_machine(Slot::Route, machine)
            .expect("install");

        static EVENT: TapEvent = TapEvent::zero();
        let enforce = run_with(&slots, Slot::Route, &EVENT, None, None, |_| {});
        assert!(matches!(
            enforce,
            Action::Abort(AbortInfo { reason: 0x1234, .. })
        ));

        slots.set_policy_mode(Slot::Route, PolicyMode::Shadow);
        let shadow = run_with(&slots, Slot::Route, &EVENT, None, None, |_| {});
        assert_eq!(shadow, Action::Proceed);
    }

    #[test]
    fn fuel_budget_resets_for_each_policy_execution() {
        static CODE: [u8; 4] = [
            ops::instr::NOP,
            ops::instr::NOP,
            ops::instr::ACT_ROUTE,
            0x00,
        ];
        let mut scratch = [0u8; 64];
        let machine = setup_machine(&CODE, &mut scratch);
        let mut slots = HostSlots::new();
        slots
            .install_machine(Slot::Route, machine)
            .expect("install");

        static EVENT: TapEvent = TapEvent::zero();
        for _ in 0..5 {
            assert_eq!(
                run_with(&slots, Slot::Route, &EVENT, None, None, |_| {}),
                Action::Route { arm: 0 }
            );
            assert_eq!(slots.last_fuel_used(Slot::Route), 3);
        }
    }

    #[test]
    fn install_verified_rechecks_slot_contract() {
        let code = [
            ops::instr::GET_INPUT,
            0x00,
            0x00,
            ops::instr::ACT_ROUTE,
            0x00,
        ];
        let header = Header {
            code_len: code.len() as u16,
            fuel_max: 8,
            mem_len: 16,
            flags: 0,
            hash: crate::verifier::compute_hash(&code),
        };
        let mut bytes = [0u8; Header::SIZE + 5];
        header.encode_into((&mut bytes[..Header::SIZE]).try_into().unwrap());
        bytes[Header::SIZE..].copy_from_slice(&code);
        let verified = VerifiedImage::new(&bytes).expect("generic image verifies");

        let mut slots = HostSlots::new();
        let mut scratch = [0u8; 16];
        let err = slots
            .install_verified(Slot::Forward, verified, ScratchLease::new(&mut scratch))
            .unwrap_err();
        assert!(matches!(
            err.error(),
            HostError::Verify(VerifyError::InputForbiddenForSlot {
                slot: Slot::Forward,
                ..
            })
        ));
    }

    #[test]
    fn uninstall_returns_same_scratch_lease_for_reinstall() {
        static CODE: [u8; 3] = [ops::instr::ACT_ABORT, 0x34, 0x12];
        let mut scratch = [0u8; 64];
        let machine = setup_machine(&CODE, &mut scratch);
        let mut slots = HostSlots::new();
        slots
            .install_machine(Slot::Route, machine)
            .expect("install");

        let scratch = slots.uninstall(Slot::Route).expect("uninstall");
        let machine =
            Machine::with_mem(&CODE, scratch, 64, 8, crate::verifier::compute_hash(&CODE))
                .expect("machine");
        slots
            .install_machine(Slot::Route, machine)
            .expect("reinstall");
    }

    #[test]
    fn install_verified_failure_returns_scratch_for_retry() {
        let oversized_code = [ops::instr::ACT_ROUTE, 0x01];
        let oversized_header = Header {
            code_len: oversized_code.len() as u16,
            fuel_max: 8,
            mem_len: 32,
            flags: 0,
            hash: crate::verifier::compute_hash(&oversized_code),
        };
        let mut oversized_bytes = [0u8; Header::SIZE + 2];
        oversized_header.encode_into((&mut oversized_bytes[..Header::SIZE]).try_into().unwrap());
        oversized_bytes[Header::SIZE..].copy_from_slice(&oversized_code);
        let oversized = VerifiedImage::new_for_slot(&oversized_bytes, Slot::Route)
            .expect("oversized image verifies");

        let retry_code = [ops::instr::ACT_ROUTE, 0x00];
        let retry_header = Header {
            code_len: retry_code.len() as u16,
            fuel_max: 8,
            mem_len: 16,
            flags: 0,
            hash: crate::verifier::compute_hash(&retry_code),
        };
        let mut retry_bytes = [0u8; Header::SIZE + 2];
        retry_header.encode_into((&mut retry_bytes[..Header::SIZE]).try_into().unwrap());
        retry_bytes[Header::SIZE..].copy_from_slice(&retry_code);
        let retry =
            VerifiedImage::new_for_slot(&retry_bytes, Slot::Route).expect("retry image verifies");

        let mut slots = HostSlots::new();
        let mut scratch = [0u8; 16];
        let err = slots
            .install_verified(Slot::Route, oversized, ScratchLease::new(&mut scratch))
            .unwrap_err();
        let (error, scratch) = err.into_parts();
        assert!(matches!(
            error,
            HostError::ScratchTooSmall {
                requested: 32,
                available: 16
            }
        ));

        slots
            .install_verified(Slot::Route, retry, scratch)
            .expect("retry install");
    }

    #[test]
    fn install_verified_slot_occupied_returns_scratch() {
        static CODE: [u8; 2] = [ops::instr::ACT_ROUTE, 0x01];
        let mut occupied_scratch = [0u8; 64];
        let machine = setup_machine(&CODE, &mut occupied_scratch);
        let mut slots = HostSlots::new();
        slots
            .install_machine(Slot::Route, machine)
            .expect("install");

        let header = Header {
            code_len: CODE.len() as u16,
            fuel_max: 8,
            mem_len: 16,
            flags: 0,
            hash: crate::verifier::compute_hash(&CODE),
        };
        let mut bytes = [0u8; Header::SIZE + 2];
        header.encode_into((&mut bytes[..Header::SIZE]).try_into().unwrap());
        bytes[Header::SIZE..].copy_from_slice(&CODE);
        let verified = VerifiedImage::new_for_slot(&bytes, Slot::Route).expect("verify");

        let mut retry_scratch = [0u8; 16];
        let err = slots
            .install_verified(Slot::Route, verified, ScratchLease::new(&mut retry_scratch))
            .unwrap_err();
        assert_eq!(err.error(), HostError::SlotOccupied);
        let recovered = err.into_scratch().into_inner();
        recovered[0] = 7;
        assert_eq!(recovered[0], 7);
    }
}
