#![cfg_attr(not(feature = "std"), no_std)]

mod ops;
mod protocol;
mod verifier;
mod vm;

use core::{
    cell::UnsafeCell,
    marker::PhantomData,
    mem::{MaybeUninit, align_of, size_of},
    ptr,
};

use hibana::runtime::{
    resolver::{DecisionArm, ResolverError, ResolverRef},
    tap::{
        Evidence, TRANSPORT_FAULT, TRANSPORT_FAULT_CAPACITY, TRANSPORT_FAULT_DEADLINE,
        TRANSPORT_MISMATCH, TRANSPORT_MISMATCH_SESSION, TapEvent,
    },
};

pub use protocol::{Protocol, ProtocolError};
pub use verifier::{Header, VerifyError, compute_hash};
pub use vm::Trap;

/// Stable hash of the Hibana Evidence ABI consumed by EPF images.
pub const EVIDENCE_SCHEMA_HASH: u32 = 0x4845_0003;

const RESOLVER_STORAGE_WORDS: usize =
    size_of::<ResolverRef<'static, 0>>().div_ceil(size_of::<usize>());

const DEFAULT_OBSERVE_FUEL: u16 = 16;

/// Policy VM `Out.kind`: choose the arm encoded in `Out.arg0`.
pub const POLICY_OUT_CHOOSE: u32 = 1;
/// Policy VM `Out.kind`: reject the policy point fail-closed.
pub const POLICY_OUT_REJECT: u32 = 2;

/// Canonical EPF VM input derived from Hibana evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvidenceInput {
    kind: u16,
    reason: u8,
    words: [u32; 4],
}

impl EvidenceInput {
    #[inline]
    pub const fn new(kind: u16, reason: u8, words: [u32; 4]) -> Self {
        Self {
            kind,
            reason,
            words,
        }
    }

    #[inline]
    pub const fn from_evidence(evidence: Evidence) -> Self {
        Self::new(evidence.kind(), evidence.reason(), evidence.input())
    }

    #[inline]
    pub const fn from_tap_event(event: TapEvent) -> Self {
        Self::from_evidence(event.evidence())
    }

    #[inline]
    pub const fn kind(self) -> u16 {
        self.kind
    }

    #[inline]
    pub const fn reason(self) -> u8 {
        self.reason
    }

    #[inline]
    pub const fn words(self) -> [u32; 4] {
        self.words
    }
}

const DEFAULT_OBSERVE_CODE: [u8; 19] = [
    ops::LOAD_KIND,
    0,
    ops::LOAD_REASON,
    1,
    ops::LOAD_INPUT,
    2,
    0,
    ops::LOAD_INPUT,
    3,
    1,
    ops::LOAD_INPUT,
    4,
    3,
    ops::EMIT,
    0,
    1,
    2,
    3,
    4,
];

/// Image address inside the single Pico-class EPF appliance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Observe,
    Policy(u16),
}

impl Target {
    #[inline]
    pub const fn encode(self) -> (u8, u16) {
        match self {
            Self::Observe => (0, 0),
            Self::Policy(policy_id) => (1, policy_id),
        }
    }

    #[inline]
    pub const fn decode(kind: u8, policy_id: u16) -> Result<Self, VerifyError> {
        match kind {
            0 if policy_id == 0 => Ok(Self::Observe),
            1 => Ok(Self::Policy(policy_id)),
            _ => Err(VerifyError::UnsupportedTarget { kind, policy_id }),
        }
    }
}

/// Compact device-side VM output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Out {
    target: Target,
    epoch: u32,
    kind: u32,
    reason: u32,
    arg0: u32,
    arg1: u32,
    arg2: u32,
    fuel_used: u16,
    trap: Option<Trap>,
}

impl Out {
    #[inline]
    pub const fn quiet(target: Target, epoch: u32, fuel_used: u16) -> Self {
        Self {
            target,
            epoch,
            kind: 0,
            reason: 0,
            arg0: 0,
            arg1: 0,
            arg2: 0,
            fuel_used,
            trap: None,
        }
    }

    #[inline]
    pub const fn emit(
        context: (Target, u32),
        [kind, reason, arg0, arg1, arg2]: [u32; 5],
        fuel_used: u16,
    ) -> Self {
        let (target, epoch) = context;
        Self {
            target,
            epoch,
            kind,
            reason,
            arg0,
            arg1,
            arg2,
            fuel_used,
            trap: None,
        }
    }

    #[inline]
    pub const fn trap(target: Target, epoch: u32, trap: Trap, fuel_used: u16) -> Self {
        Self {
            target,
            epoch,
            kind: 0xffff,
            reason: trap_code(trap),
            arg0: 0,
            arg1: 0,
            arg2: 0,
            fuel_used,
            trap: Some(trap),
        }
    }

    #[inline]
    pub const fn target(self) -> Target {
        self.target
    }

    #[inline]
    pub const fn epoch(self) -> u32 {
        self.epoch
    }

    #[inline]
    pub const fn kind(self) -> u32 {
        self.kind
    }

    #[inline]
    pub const fn reason(self) -> u32 {
        self.reason
    }

    #[inline]
    pub const fn arg0(self) -> u32 {
        self.arg0
    }

    #[inline]
    pub const fn arg1(self) -> u32 {
        self.arg1
    }

    #[inline]
    pub const fn arg2(self) -> u32 {
        self.arg2
    }

    #[inline]
    pub const fn fuel_used(self) -> u16 {
        self.fuel_used
    }

    #[inline]
    pub const fn trap_reason(self) -> Option<Trap> {
        self.trap
    }

    #[inline]
    pub const fn emitted(self) -> bool {
        self.kind != 0 || self.trap.is_some()
    }
}

const fn trap_code(trap: Trap) -> u32 {
    match trap {
        Trap::FuelExhausted => 1,
        Trap::IllegalOpcode(opcode) => 0x100 | opcode as u32,
        Trap::VerifyFailed => 3,
    }
}

/// Successful load report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Load {
    target: Target,
    epoch: u32,
    digest: u32,
    code_len: u16,
}

impl Load {
    #[inline]
    pub const fn target(self) -> Target {
        self.target
    }

    #[inline]
    pub const fn epoch(self) -> u32 {
        self.epoch
    }

    #[inline]
    pub const fn digest(self) -> u32 {
        self.digest
    }

    #[inline]
    pub const fn code_len(self) -> u16 {
        self.code_len
    }
}

/// EPF appliance error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Verify(VerifyError),
    ImageTooLarge { requested: usize, capacity: usize },
    PolicySlotUnavailable { policy_id: u16 },
    NoImage { target: Target },
    NoPrevious { target: Target },
}

impl From<VerifyError> for Error {
    #[inline]
    fn from(error: VerifyError) -> Self {
        Self::Verify(error)
    }
}

/// Ready-made EPF image recipes for the common Pico-class debug path.
///
/// This is a value spec, not a runtime object. It exists so users do not need
/// to hand-write bytecode for the standard observe and policy proofs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageSpec {
    /// Observe VM that emits kind/reason, the first two inputs and packed context.
    ObserveEcho,
    /// Observe VM for transport session mismatch evidence.
    ObserveSessionMismatch,
    /// Observe VM for transport deadline fault evidence.
    ObserveDeadlineFault,
    /// Observe VM for transport capacity fault evidence.
    ObserveCapacityFault,
    /// Observe VM that emits only when one typed input word matches.
    ObserveMatch {
        input: u8,
        value: u32,
        kind: u32,
        reason: u32,
    },
    /// Policy VM that always chooses one binary arm.
    PolicyChoose { policy_id: u16, arm: u8 },
    /// Choose an arm when one input matches; otherwise reject the decision.
    PolicyChooseOnInput {
        policy_id: u16,
        input: u8,
        value: u32,
        arm: u8,
    },
}

impl ImageSpec {
    pub fn write(self, out: &mut [u8]) -> Result<usize, ImageBuildError> {
        self.write_with_fuel(out, 32)
    }

    pub fn write_with_fuel(self, out: &mut [u8], fuel_max: u16) -> Result<usize, ImageBuildError> {
        if fuel_max == 0 {
            return Err(ImageBuildError::ZeroFuel);
        }
        if out.len() < Header::SIZE {
            return Err(ImageBuildError::OutputTooSmall {
                requested: Header::SIZE,
                capacity: out.len(),
            });
        }
        let target = self.target();
        let code_len = {
            let mut writer = CodeWriter::new(&mut out[Header::SIZE..]);
            self.write_code(&mut writer)?;
            writer.len()
        };
        if code_len > u16::MAX as usize {
            return Err(ImageBuildError::CodeTooLong { len: code_len });
        }
        let total = Header::SIZE + code_len;
        let header = Header {
            abi: Header::ABI,
            target,
            schema_hash: EVIDENCE_SCHEMA_HASH,
            code_len: code_len as u16,
            fuel_max,
            mem_len: 0,
            code_hash: compute_hash(&out[Header::SIZE..total]),
        };
        let mut header_bytes = [0u8; Header::SIZE];
        header.encode_into(&mut header_bytes);
        out[..Header::SIZE].copy_from_slice(&header_bytes);
        Ok(total)
    }

    fn target(self) -> Target {
        match self {
            Self::ObserveEcho
            | Self::ObserveSessionMismatch
            | Self::ObserveDeadlineFault
            | Self::ObserveCapacityFault
            | Self::ObserveMatch { .. } => Target::Observe,
            Self::PolicyChoose { policy_id, .. } | Self::PolicyChooseOnInput { policy_id, .. } => {
                Target::Policy(policy_id)
            }
        }
    }

    fn write_code(self, writer: &mut CodeWriter<'_>) -> Result<(), ImageBuildError> {
        match self {
            Self::ObserveEcho => writer.bytes(&DEFAULT_OBSERVE_CODE),
            Self::ObserveSessionMismatch => write_observe_kind_reason(
                writer,
                TRANSPORT_MISMATCH,
                TRANSPORT_MISMATCH_SESSION,
                1,
                TRANSPORT_MISMATCH_SESSION as u32,
            ),
            Self::ObserveDeadlineFault => write_observe_kind_reason(
                writer,
                TRANSPORT_FAULT,
                TRANSPORT_FAULT_DEADLINE,
                2,
                TRANSPORT_FAULT_DEADLINE as u32,
            ),
            Self::ObserveCapacityFault => write_observe_kind_reason(
                writer,
                TRANSPORT_FAULT,
                TRANSPORT_FAULT_CAPACITY,
                2,
                TRANSPORT_FAULT_CAPACITY as u32,
            ),
            Self::ObserveMatch {
                input,
                value,
                kind,
                reason,
            } => {
                validate_input(input)?;
                write_observe_input_match(writer, input, value, kind, reason)
            }
            Self::PolicyChoose { arm, .. } => {
                validate_arm(arm)?;
                writer_policy_choose(writer, arm)
            }
            Self::PolicyChooseOnInput {
                input, value, arm, ..
            } => {
                validate_input(input)?;
                validate_arm(arm)?;
                writer.require_input_eq(input, value)?;
                writer_policy_choose(writer, arm)
            }
        }
    }
}

fn write_observe_kind_reason(
    writer: &mut CodeWriter<'_>,
    kind_id: u16,
    reason_id: u8,
    kind: u32,
    reason: u32,
) -> Result<(), ImageBuildError> {
    writer.require_kind(kind_id)?;
    writer.require_reason(reason_id)?;
    writer.load_imm(0, kind)?;
    writer.load_imm(1, reason)?;
    writer.load_input(2, 0)?;
    writer.load_input(3, 1)?;
    writer.load_input(4, 3)?;
    writer.emit(0, 1, 2, 3, 4)?;
    writer.halt()
}

fn write_observe_input_match(
    writer: &mut CodeWriter<'_>,
    input: u8,
    value: u32,
    kind: u32,
    reason: u32,
) -> Result<(), ImageBuildError> {
    writer.require_input_eq(input, value)?;
    writer.load_imm(0, kind)?;
    writer.load_imm(1, reason)?;
    writer.load_input(2, 0)?;
    writer.load_input(3, 1)?;
    writer.load_input(4, 3)?;
    writer.emit(0, 1, 2, 3, 4)?;
    writer.halt()
}

fn writer_policy_choose(writer: &mut CodeWriter<'_>, arm: u8) -> Result<(), ImageBuildError> {
    writer.load_imm(0, POLICY_OUT_CHOOSE)?;
    writer.load_imm(1, 0)?;
    writer.load_imm(2, arm as u32)?;
    writer.emit(0, 1, 2, 1, 1)?;
    writer.halt()
}

fn validate_input(input: u8) -> Result<(), ImageBuildError> {
    if input > 3 {
        Err(ImageBuildError::InvalidInputIndex { input })
    } else {
        Ok(())
    }
}

fn validate_arm(arm: u8) -> Result<(), ImageBuildError> {
    if arm > 1 {
        Err(ImageBuildError::InvalidArm { arm })
    } else {
        Ok(())
    }
}

struct CodeWriter<'a> {
    out: &'a mut [u8],
    len: usize,
}

impl<'a> CodeWriter<'a> {
    fn new(out: &'a mut [u8]) -> Self {
        Self { out, len: 0 }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn bytes(&mut self, bytes: &[u8]) -> Result<(), ImageBuildError> {
        let end = self.len.saturating_add(bytes.len());
        let Some(dst) = self.out.get_mut(self.len..end) else {
            return Err(ImageBuildError::OutputTooSmall {
                requested: Header::SIZE + end,
                capacity: Header::SIZE + self.out.len(),
            });
        };
        dst.copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }

    fn byte(&mut self, byte: u8) -> Result<(), ImageBuildError> {
        self.bytes(&[byte])
    }

    fn u32(&mut self, value: u32) -> Result<(), ImageBuildError> {
        self.bytes(&value.to_le_bytes())
    }

    fn load_input(&mut self, reg: u8, input: u8) -> Result<(), ImageBuildError> {
        self.byte(ops::LOAD_INPUT)?;
        self.byte(reg)?;
        self.byte(input)
    }

    fn load_imm(&mut self, reg: u8, value: u32) -> Result<(), ImageBuildError> {
        self.byte(ops::LOAD_IMM)?;
        self.byte(reg)?;
        self.u32(value)
    }

    fn require_input_eq(&mut self, input: u8, value: u32) -> Result<(), ImageBuildError> {
        self.byte(ops::REQUIRE_INPUT_EQ)?;
        self.byte(input)?;
        self.u32(value)
    }

    fn require_kind(&mut self, kind: u16) -> Result<(), ImageBuildError> {
        self.byte(ops::REQUIRE_KIND)?;
        self.bytes(&kind.to_le_bytes())
    }

    fn require_reason(&mut self, reason: u8) -> Result<(), ImageBuildError> {
        self.byte(ops::REQUIRE_REASON)?;
        self.byte(reason)
    }

    fn emit(
        &mut self,
        kind: u8,
        reason: u8,
        arg0: u8,
        arg1: u8,
        arg2: u8,
    ) -> Result<(), ImageBuildError> {
        self.byte(ops::EMIT)?;
        self.byte(kind)?;
        self.byte(reason)?;
        self.byte(arg0)?;
        self.byte(arg1)?;
        self.byte(arg2)
    }

    fn halt(&mut self) -> Result<(), ImageBuildError> {
        self.byte(ops::HALT)
    }
}

/// EPF image recipe build failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageBuildError {
    OutputTooSmall { requested: usize, capacity: usize },
    CodeTooLong { len: usize },
    InvalidInputIndex { input: u8 },
    InvalidArm { arm: u8 },
    ZeroFuel,
}

/// Generic EPF image envelope parser.
///
/// This is byte-stream state only. UART, USB, debug-probe memory, SIO, and
/// choreography payloads remain caller-owned I/O. The envelope is:
///
/// ```text
/// b"HEPF" | image_len:u16-le | image_hash:u32-le | image_bytes
/// ```
pub struct ImageIngress<const IMAGE_BYTES: usize> {
    image: [u8; IMAGE_BYTES],
    pos: usize,
    len: usize,
    expected_hash: u32,
    running_hash: u32,
    ready: bool,
}

impl<const IMAGE_BYTES: usize> ImageIngress<IMAGE_BYTES> {
    pub const MAGIC: [u8; 4] = *b"HEPF";
    pub const HEADER_BYTES: usize = 10;

    #[inline]
    pub const fn new() -> Self {
        Self {
            image: [0; IMAGE_BYTES],
            pos: 0,
            len: 0,
            expected_hash: 0,
            running_hash: FNV32_OFFSET,
            ready: false,
        }
    }

    pub fn push(&mut self, byte: u8) -> ImageIngressStatus {
        if self.ready {
            return ImageIngressStatus::Ready {
                len: self.len,
                hash: self.expected_hash,
            };
        }

        if self.pos < Self::MAGIC.len() {
            if byte == Self::MAGIC[self.pos] {
                self.pos += 1;
                if self.pos == Self::MAGIC.len() {
                    self.len = 0;
                    self.expected_hash = 0;
                    self.running_hash = FNV32_OFFSET;
                }
                return ImageIngressStatus::Pending;
            }
            let position = self.pos as u8;
            self.restart_with(byte);
            return ImageIngressStatus::Rejected(ImageIngressReject::BadMagic { position, byte });
        }

        match self.pos {
            4 => {
                self.len = byte as usize;
                self.pos = 5;
                ImageIngressStatus::Pending
            }
            5 => {
                self.len |= (byte as usize) << 8;
                if self.len == 0 {
                    self.restart_with(byte);
                    return ImageIngressStatus::Rejected(ImageIngressReject::EmptyImage);
                }
                if self.len > IMAGE_BYTES {
                    let len = self.len;
                    self.restart_with(byte);
                    return ImageIngressStatus::Rejected(ImageIngressReject::ImageTooLarge {
                        len,
                        capacity: IMAGE_BYTES,
                    });
                }
                self.pos = 6;
                ImageIngressStatus::Pending
            }
            6..=9 => {
                let shift = ((self.pos - 6) * 8) as u32;
                self.expected_hash |= (byte as u32) << shift;
                self.pos += 1;
                ImageIngressStatus::Pending
            }
            _ => {
                let image_index = self.pos - Self::HEADER_BYTES;
                if image_index >= self.len || image_index >= IMAGE_BYTES {
                    self.restart_with(byte);
                    return ImageIngressStatus::Rejected(ImageIngressReject::Overrun);
                }
                self.image[image_index] = byte;
                self.running_hash = hash_byte(self.running_hash, byte);
                self.pos += 1;
                if image_index + 1 == self.len {
                    if self.running_hash == self.expected_hash {
                        self.ready = true;
                        self.pos = 0;
                        ImageIngressStatus::Ready {
                            len: self.len,
                            hash: self.expected_hash,
                        }
                    } else {
                        let expected = self.expected_hash;
                        let computed = self.running_hash;
                        self.reset();
                        ImageIngressStatus::Rejected(ImageIngressReject::HashMismatch {
                            expected,
                            computed,
                        })
                    }
                } else {
                    ImageIngressStatus::Pending
                }
            }
        }
    }

    #[inline]
    pub fn image(&self) -> Option<&[u8]> {
        if self.ready {
            Some(&self.image[..self.len])
        } else {
            None
        }
    }

    #[inline]
    pub const fn is_ready(&self) -> bool {
        self.ready
    }

    #[inline]
    pub const fn len(&self) -> usize {
        if self.ready { self.len } else { 0 }
    }

    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    pub const fn expected_hash(&self) -> u32 {
        self.expected_hash
    }

    #[inline]
    pub fn clear_ready(&mut self) {
        self.reset();
    }

    #[inline]
    pub const fn position(&self) -> usize {
        self.pos
    }

    #[inline]
    pub const fn staged_len(&self) -> usize {
        self.len
    }

    #[inline]
    pub const fn running_hash(&self) -> u32 {
        self.running_hash
    }

    pub fn reset(&mut self) {
        self.pos = 0;
        self.len = 0;
        self.expected_hash = 0;
        self.running_hash = FNV32_OFFSET;
        self.ready = false;
    }

    fn restart_with(&mut self, byte: u8) {
        self.reset();
        if byte == Self::MAGIC[0] {
            self.pos = 1;
        }
    }
}

impl<const IMAGE_BYTES: usize> Default for ImageIngress<IMAGE_BYTES> {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of feeding one byte into `ImageIngress`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageIngressStatus {
    Pending,
    Ready { len: usize, hash: u32 },
    Rejected(ImageIngressReject),
}

/// Rejection raised by the generic image envelope parser.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageIngressReject {
    BadMagic { position: u8, byte: u8 },
    EmptyImage,
    ImageTooLarge { len: usize, capacity: usize },
    HashMismatch { expected: u32, computed: u32 },
    Overrun,
}

/// Fixed TapEvent retention spool for loaded-bytecode diagnosis.
///
/// The spool does not read Hibana state by itself and does not run the VM. A
/// caller retains events with `push` while the system is misbehaving, then
/// replays retained events through `Epf::run_spool` after an observe image is
/// loaded.
pub struct TapSpool<const HISTORY: usize> {
    events: [MaybeUninit<TapEvent>; HISTORY],
    len: usize,
    read: usize,
}

impl<const HISTORY: usize> TapSpool<HISTORY> {
    #[inline]
    pub const fn new() -> Self {
        Self {
            events: [const { MaybeUninit::uninit() }; HISTORY],
            len: 0,
            read: 0,
        }
    }

    #[inline]
    pub fn push(&mut self, event: TapEvent) -> Result<(), TapSpoolFull> {
        if self.len >= HISTORY {
            return Err(TapSpoolFull);
        }
        self.events[self.len].write(event);
        self.len += 1;
        Ok(())
    }

    #[inline]
    pub fn next_event(&mut self) -> Option<TapEvent> {
        if self.read >= self.len {
            return None;
        }
        let event = unsafe { self.events[self.read].assume_init_read() };
        self.read += 1;
        Some(event)
    }

    #[inline]
    pub const fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub const fn pending(&self) -> usize {
        self.len.saturating_sub(self.read)
    }

    #[inline]
    pub const fn capacity(&self) -> usize {
        HISTORY
    }

    #[inline]
    pub const fn is_full(&self) -> bool {
        self.len == HISTORY
    }

    #[inline]
    pub fn rewind(&mut self) {
        self.read = 0;
    }

    #[inline]
    pub fn clear(&mut self) {
        self.len = 0;
        self.read = 0;
    }
}

impl<const HISTORY: usize> Default for TapSpool<HISTORY> {
    fn default() -> Self {
        Self::new()
    }
}

/// Returned when a fixed TapEvent spool is full.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TapSpoolFull;

/// Compact binary record for carrying `Out` over UART, USB, SIO, files, or RAM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompactOutRecord {
    pub site: u8,
    pub target: Target,
    pub epoch: u32,
    pub kind: u32,
    pub reason: u32,
    pub arg0: u32,
    pub arg1: u32,
    pub arg2: u32,
    pub fuel_used: u16,
    pub flags: u16,
}

impl CompactOutRecord {
    pub const MAGIC: [u8; 4] = *b"HEPO";
    pub const SIZE: usize = 36;
    pub const FLAG_TRAP: u16 = 1;

    #[inline]
    pub const fn from_out(site: u8, out: Out) -> Self {
        let flags = if out.trap_reason().is_some() {
            Self::FLAG_TRAP
        } else {
            0
        };
        Self {
            site,
            target: out.target(),
            epoch: out.epoch(),
            kind: out.kind(),
            reason: out.reason(),
            arg0: out.arg0(),
            arg1: out.arg1(),
            arg2: out.arg2(),
            fuel_used: out.fuel_used(),
            flags,
        }
    }

    pub fn encode(self, out: &mut [u8; Self::SIZE]) {
        let (target_kind, policy_id) = self.target.encode();
        out[0..4].copy_from_slice(&Self::MAGIC);
        out[4] = self.site;
        out[5] = target_kind;
        out[6..8].copy_from_slice(&policy_id.to_le_bytes());
        out[8..12].copy_from_slice(&self.epoch.to_le_bytes());
        out[12..16].copy_from_slice(&self.kind.to_le_bytes());
        out[16..20].copy_from_slice(&self.reason.to_le_bytes());
        out[20..24].copy_from_slice(&self.arg0.to_le_bytes());
        out[24..28].copy_from_slice(&self.arg1.to_le_bytes());
        out[28..32].copy_from_slice(&self.arg2.to_le_bytes());
        out[32..34].copy_from_slice(&self.fuel_used.to_le_bytes());
        out[34..36].copy_from_slice(&self.flags.to_le_bytes());
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CompactOutDecodeError> {
        if bytes.len() != Self::SIZE {
            return Err(CompactOutDecodeError::BadLength {
                expected: Self::SIZE,
                actual: bytes.len(),
            });
        }
        if bytes[0..4] != Self::MAGIC {
            return Err(CompactOutDecodeError::BadMagic);
        }
        let policy_id = u16::from_le_bytes([bytes[6], bytes[7]]);
        let target = Target::decode(bytes[5], policy_id)
            .map_err(CompactOutDecodeError::UnsupportedTarget)?;
        Ok(Self {
            site: bytes[4],
            target,
            epoch: u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            kind: u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
            reason: u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]),
            arg0: u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]),
            arg1: u32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]),
            arg2: u32::from_le_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]),
            fuel_used: u16::from_le_bytes([bytes[32], bytes[33]]),
            flags: u16::from_le_bytes([bytes[34], bytes[35]]),
        })
    }
}

/// Compact output record decode failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompactOutDecodeError {
    BadLength { expected: usize, actual: usize },
    BadMagic,
    UnsupportedTarget(VerifyError),
}

const FNV32_OFFSET: u32 = 0x811C_9DC5;
const FNV32_PRIME: u32 = 0x0100_0193;

#[inline]
const fn hash_byte(hash: u32, byte: u8) -> u32 {
    (hash ^ byte as u32).wrapping_mul(FNV32_PRIME)
}

/// Fixed storage owned by the caller. Pico class is the standard capacity model.
pub struct EpfStorage<'cfg, const POLICY_SLOTS: usize, const IMAGE_BYTES: usize> {
    inner: UnsafeCell<StorageInner<'cfg, POLICY_SLOTS, IMAGE_BYTES>>,
    _not_sync: PhantomData<*mut ()>,
}

impl<'cfg, const POLICY_SLOTS: usize, const IMAGE_BYTES: usize>
    EpfStorage<'cfg, POLICY_SLOTS, IMAGE_BYTES>
{
    pub const fn new() -> Self {
        Self {
            inner: UnsafeCell::new(StorageInner::new()),
            _not_sync: PhantomData,
        }
    }
}

impl<'cfg, const POLICY_SLOTS: usize, const IMAGE_BYTES: usize> Default
    for EpfStorage<'cfg, POLICY_SLOTS, IMAGE_BYTES>
{
    fn default() -> Self {
        Self::new()
    }
}

struct StorageInner<'cfg, const POLICY_SLOTS: usize, const IMAGE_BYTES: usize> {
    observe: ImageBank<IMAGE_BYTES>,
    policies: [PolicySlot<'cfg, IMAGE_BYTES>; POLICY_SLOTS],
    evidence: EvidenceState,
}

impl<'cfg, const POLICY_SLOTS: usize, const IMAGE_BYTES: usize>
    StorageInner<'cfg, POLICY_SLOTS, IMAGE_BYTES>
{
    const fn new() -> Self {
        Self {
            observe: ImageBank::new(),
            policies: [const { PolicySlot::new() }; POLICY_SLOTS],
            evidence: EvidenceState::new(),
        }
    }
    fn register_policy(
        &mut self,
        policy_id: u16,
    ) -> Result<&mut PolicySlot<'cfg, IMAGE_BYTES>, Error> {
        let mut empty = None;
        let mut idx = 0usize;
        while idx < self.policies.len() {
            if self.policies[idx].policy_id == Some(policy_id) {
                return Ok(&mut self.policies[idx]);
            }
            if self.policies[idx].policy_id.is_none() && empty.is_none() {
                empty = Some(idx);
            }
            idx += 1;
        }
        if let Some(idx) = empty {
            self.policies[idx].policy_id = Some(policy_id);
            return Ok(&mut self.policies[idx]);
        }
        Err(Error::PolicySlotUnavailable { policy_id })
    }

    fn policy_slot_mut(&mut self, policy_id: u16) -> Option<&mut PolicySlot<'cfg, IMAGE_BYTES>> {
        self.policies
            .iter_mut()
            .find(|slot| slot.policy_id == Some(policy_id))
    }
}

struct PolicySlot<'cfg, const IMAGE_BYTES: usize> {
    policy_id: Option<u16>,
    bank: ImageBank<IMAGE_BYTES>,
    fallback: Option<StoredResolver<'cfg>>,
}

impl<'cfg, const IMAGE_BYTES: usize> PolicySlot<'cfg, IMAGE_BYTES> {
    const fn new() -> Self {
        Self {
            policy_id: None,
            bank: ImageBank::new(),
            fallback: None,
        }
    }
}

#[derive(Clone, Copy)]
struct StoredResolver<'cfg> {
    words: [MaybeUninit<usize>; RESOLVER_STORAGE_WORDS],
    _marker: PhantomData<&'cfg ()>,
}

impl<'cfg> StoredResolver<'cfg> {
    fn new<const POLICY_ID: u16>(resolver: ResolverRef<'cfg, POLICY_ID>) -> Self {
        assert!(
            size_of::<ResolverRef<'cfg, POLICY_ID>>()
                <= size_of::<[MaybeUninit<usize>; RESOLVER_STORAGE_WORDS]>()
        );
        assert!(
            align_of::<ResolverRef<'cfg, POLICY_ID>>()
                <= align_of::<[MaybeUninit<usize>; RESOLVER_STORAGE_WORDS]>()
        );
        let mut stored = Self {
            words: [MaybeUninit::zeroed(); RESOLVER_STORAGE_WORDS],
            _marker: PhantomData,
        };
        unsafe {
            ptr::copy_nonoverlapping(
                ptr::from_ref(&resolver).cast::<u8>(),
                stored.words.as_mut_ptr().cast::<u8>(),
                size_of::<ResolverRef<'cfg, POLICY_ID>>(),
            );
        }
        stored
    }

    fn resolve<const POLICY_ID: u16>(self) -> Result<DecisionArm, ResolverError> {
        assert!(
            size_of::<ResolverRef<'cfg, POLICY_ID>>()
                <= size_of::<[MaybeUninit<usize>; RESOLVER_STORAGE_WORDS]>()
        );
        assert!(
            align_of::<ResolverRef<'cfg, POLICY_ID>>()
                <= align_of::<[MaybeUninit<usize>; RESOLVER_STORAGE_WORDS]>()
        );
        let mut resolver = MaybeUninit::<ResolverRef<'cfg, POLICY_ID>>::uninit();
        unsafe {
            ptr::copy_nonoverlapping(
                self.words.as_ptr().cast::<u8>(),
                resolver.as_mut_ptr().cast::<u8>(),
                size_of::<ResolverRef<'cfg, POLICY_ID>>(),
            );
            resolver.assume_init().decide()
        }
    }
}

struct ImageBank<const IMAGE_BYTES: usize> {
    image: [[u8; IMAGE_BYTES]; 2],
    len: [usize; 2],
    fuel_max: [u16; 2],
    active: u8,
    previous: u8,
    has_active: bool,
    has_previous: bool,
    epoch: u32,
}

impl<const IMAGE_BYTES: usize> ImageBank<IMAGE_BYTES> {
    const fn new() -> Self {
        Self {
            image: [[0; IMAGE_BYTES]; 2],
            len: [0; 2],
            fuel_max: [0; 2],
            active: 0,
            previous: 1,
            has_active: false,
            has_previous: false,
            epoch: 0,
        }
    }

    fn load(&mut self, verified: verifier::VerifiedImage<'_>) -> Load {
        let image = verified.bytes;
        let inactive = if self.has_active {
            1usize.saturating_sub(self.active as usize)
        } else {
            self.active as usize
        };
        self.image[inactive][..image.len()].copy_from_slice(image);
        zero(&mut self.image[inactive][image.len()..]);
        self.len[inactive] = image.len();
        self.fuel_max[inactive] = verified.header.fuel_max;

        if self.has_active {
            self.previous = self.active;
            self.has_previous = true;
        }
        self.active = inactive as u8;
        self.has_active = true;
        self.epoch = self.epoch.wrapping_add(1);

        Load {
            target: verified.header.target,
            epoch: self.epoch,
            digest: verified.header.code_hash,
            code_len: verified.header.code_len,
        }
    }

    fn unload(&mut self, target: Target) -> Result<(), Error> {
        if !self.has_active {
            return Err(Error::NoImage { target });
        }
        self.has_active = false;
        self.epoch = self.epoch.wrapping_add(1);
        Ok(())
    }

    fn revert(&mut self, target: Target) -> Result<(), Error> {
        if !self.has_previous {
            return Err(Error::NoPrevious { target });
        }
        core::mem::swap(&mut self.active, &mut self.previous);
        self.has_active = true;
        self.epoch = self.epoch.wrapping_add(1);
        Ok(())
    }

    fn run(&self, target: Target, input: vm::VmInput) -> Out {
        if !self.has_active {
            return Out::quiet(target, self.epoch, 0);
        }
        let index = self.active as usize;
        let image = &self.image[index][..self.len[index]];
        let code = &image[Header::SIZE..];
        vm::run(target, self.epoch, code, input, self.fuel_max[index])
    }
}

#[derive(Clone, Copy)]
struct EvidenceState {
    latest: [u32; 4],
    latest_kind: u16,
    latest_reason: u8,
    observe_epoch: u32,
}

impl EvidenceState {
    const fn new() -> Self {
        Self {
            latest: [0; 4],
            latest_kind: 0,
            latest_reason: 0,
            observe_epoch: 0,
        }
    }

    fn ingest(&mut self, evidence: EvidenceInput) {
        let input = evidence.words();
        self.latest = input;
        self.latest_kind = evidence.kind();
        self.latest_reason = evidence.reason();
        self.observe_epoch = self.observe_epoch.wrapping_add(1);
    }
}

/// The single EPF runtime appliance.
pub struct Epf<'a, const POLICY_SLOTS: usize, const IMAGE_BYTES: usize> {
    inner: &'a UnsafeCell<StorageInner<'a, POLICY_SLOTS, IMAGE_BYTES>>,
}

impl<'a, const POLICY_SLOTS: usize, const IMAGE_BYTES: usize> Epf<'a, POLICY_SLOTS, IMAGE_BYTES> {
    #[inline]
    pub fn new(storage: &'a mut EpfStorage<'a, POLICY_SLOTS, IMAGE_BYTES>) -> Self {
        Self {
            inner: &storage.inner,
        }
    }

    pub fn load(&self, image: &[u8]) -> Result<Load, Error> {
        let verified = verifier::VerifiedImage::new(image)?;
        if image.len() > IMAGE_BYTES {
            return Err(Error::ImageTooLarge {
                requested: image.len(),
                capacity: IMAGE_BYTES,
            });
        }
        self.with_inner(|inner| {
            Ok(match verified.header.target {
                Target::Observe => inner.observe.load(verified),
                Target::Policy(policy_id) => inner.register_policy(policy_id)?.bank.load(verified),
            })
        })
    }

    /// Load a ready generic image ingress envelope.
    ///
    /// Returns `Ok(None)` when the ingress has not completed an image yet. A
    /// successful load clears the ready image; a failed load leaves it available
    /// for caller-side diagnostics.
    pub fn load_ingress<const INGRESS_BYTES: usize>(
        &self,
        ingress: &mut ImageIngress<INGRESS_BYTES>,
    ) -> Result<Option<Load>, Error> {
        let Some(image) = ingress.image() else {
            return Ok(None);
        };
        let loaded = self.load(image)?;
        ingress.clear_ready();
        Ok(Some(loaded))
    }

    pub fn unload(&self, target: Target) -> Result<(), Error> {
        self.with_inner(|inner| match target {
            Target::Observe => inner.observe.unload(target),
            Target::Policy(policy_id) => inner
                .policy_slot_mut(policy_id)
                .ok_or(Error::NoImage { target })?
                .bank
                .unload(target),
        })
    }

    pub fn revert(&self, target: Target) -> Result<(), Error> {
        self.with_inner(|inner| match target {
            Target::Observe => inner.observe.revert(target),
            Target::Policy(policy_id) => inner
                .policy_slot_mut(policy_id)
                .ok_or(Error::NoPrevious { target })?
                .bank
                .revert(target),
        })
    }

    /// Run the observe VM over one Hibana tap event.
    pub fn run(&self, event: TapEvent) -> Out {
        self.run_evidence(EvidenceInput::from_tap_event(event))
    }

    /// Run the observe VM over one canonical EPF evidence input.
    pub fn run_evidence(&self, evidence: EvidenceInput) -> Out {
        let input = vm_input(evidence);
        self.with_inner(|inner| {
            inner.evidence.ingest(evidence);
            if inner.observe.has_active {
                inner.observe.run(Target::Observe, input)
            } else {
                vm::run(
                    Target::Observe,
                    inner.evidence.observe_epoch,
                    &DEFAULT_OBSERVE_CODE,
                    input,
                    DEFAULT_OBSERVE_FUEL,
                )
            }
        })
    }

    /// Replay retained TapEvents until the VM emits a compact output.
    pub fn run_spool<const RETAINED: usize>(&self, spool: &mut TapSpool<RETAINED>) -> Option<Out> {
        while let Some(event) = spool.next_event() {
            let out = self.run(event);
            if out.emitted() {
                return Some(out);
            }
        }
        None
    }

    pub fn resolver<const POLICY_ID: u16>(
        &'a self,
        fallback: ResolverRef<'a, POLICY_ID>,
    ) -> Result<ResolverRef<'a, POLICY_ID>, Error> {
        self.with_inner(|inner| -> Result<(), Error> {
            inner.register_policy(POLICY_ID)?.fallback = Some(StoredResolver::new(fallback));
            Ok(())
        })?;
        Ok(ResolverRef::decision_state(
            self,
            Self::resolve_policy::<POLICY_ID>,
        ))
    }

    fn resolve_policy<const POLICY_ID: u16>(epf: &Self) -> Result<DecisionArm, ResolverError> {
        let decision = epf.with_inner(|inner| {
            let input = vm::VmInput {
                kind: inner.evidence.latest_kind,
                reason: inner.evidence.latest_reason,
                words: inner.evidence.latest,
            };
            for slot in &inner.policies {
                if slot.policy_id == Some(POLICY_ID) {
                    return if slot.bank.has_active {
                        Ok(slot.bank.run(Target::Policy(POLICY_ID), input))
                    } else {
                        Err(slot.fallback)
                    };
                }
            }
            Err(None)
        });
        match decision {
            Ok(out) => policy_resolution(out),
            Err(Some(fallback)) => fallback.resolve::<POLICY_ID>(),
            Err(None) => Err(ResolverError::reject()),
        }
    }

    fn with_inner<T>(
        &self,
        apply: impl FnOnce(&mut StorageInner<'a, POLICY_SLOTS, IMAGE_BYTES>) -> T,
    ) -> T {
        // SAFETY: Epf uniquely borrows its storage and is neither Send nor Sync.
        // Every caller is private, exposes no storage borrow and invokes no user
        // callback while this borrow lives. Resolver callbacks run afterwards.
        apply(unsafe { &mut *self.inner.get() })
    }
}

fn policy_resolution(out: Out) -> Result<DecisionArm, ResolverError> {
    if out.trap_reason().is_some() {
        return Err(ResolverError::reject());
    }
    match out.kind() {
        POLICY_OUT_CHOOSE => match out.arg0() {
            0 => Ok(DecisionArm::Left),
            1 => Ok(DecisionArm::Right),
            _ => Err(ResolverError::reject()),
        },
        POLICY_OUT_REJECT => Err(ResolverError::reject()),
        _ => Err(ResolverError::reject()),
    }
}

#[inline]
fn vm_input(evidence: EvidenceInput) -> vm::VmInput {
    vm::VmInput {
        kind: evidence.kind(),
        reason: evidence.reason(),
        words: evidence.words(),
    }
}

fn zero(bytes: &mut [u8]) {
    for byte in bytes {
        *byte = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hibana::runtime::tap::{TRANSPORT_MISMATCH, TRANSPORT_MISMATCH_SESSION};

    fn image(target: Target, code: &[u8], out: &mut [u8]) -> usize {
        let header = Header {
            abi: Header::ABI,
            target,
            schema_hash: EVIDENCE_SCHEMA_HASH,
            code_len: code.len() as u16,
            fuel_max: 32,
            mem_len: 0,
            code_hash: compute_hash(code),
        };
        let mut encoded = [0u8; Header::SIZE];
        header.encode_into(&mut encoded);
        out[..Header::SIZE].copy_from_slice(&encoded);
        out[Header::SIZE..Header::SIZE + code.len()].copy_from_slice(code);
        Header::SIZE + code.len()
    }

    fn mismatch_event() -> TapEvent {
        TapEvent::from([
            0, 0, 0, 1, 0x02, 0x05, 0, 1, 0x11, 0x11, 0, 1, 0x22, 0x22, 0, 1,
        ])
    }

    #[test]
    fn default_observe_vm_reports_tap_event() {
        let mut storage = EpfStorage::<1, 64>::new();
        let epf = Epf::new(&mut storage);

        let out = epf.run(mismatch_event());

        assert_eq!(out.target(), Target::Observe);
        assert_eq!(out.kind(), TRANSPORT_MISMATCH as u32);
        assert_eq!(out.reason(), TRANSPORT_MISMATCH_SESSION as u32);
        assert_eq!(out.arg0(), 0x1111_0001);
        assert_eq!(out.arg1(), 0x2222_0001);
        assert_eq!(out.arg2(), 0x0205_0001);
        assert_eq!(out.fuel_used(), 6);
    }

    #[test]
    fn load_replaces_observe_vm_without_public_slots() {
        let code = [
            ops::REQUIRE_INPUT_EQ,
            3,
            0x01,
            0x00,
            0x05,
            0x02,
            ops::LOAD_IMM,
            0,
            1,
            0,
            0,
            0,
            ops::LOAD_IMM,
            1,
            1,
            0,
            0,
            0,
            ops::LOAD_INPUT,
            2,
            0,
            ops::LOAD_INPUT,
            3,
            1,
            ops::LOAD_INPUT,
            4,
            2,
            ops::EMIT,
            0,
            1,
            2,
            3,
            4,
            ops::HALT,
        ];
        let mut bytes = [0u8; 64];
        let len = image(Target::Observe, &code, &mut bytes);
        let mut storage = EpfStorage::<1, 64>::new();
        let epf = Epf::new(&mut storage);

        let load = epf.load(&bytes[..len]).expect("load");
        let out = epf.run(mismatch_event());

        assert_eq!(load.target(), Target::Observe);
        assert_eq!(out.epoch(), load.epoch());
        assert_eq!(out.kind(), 1);
        assert_eq!(out.reason(), 1);
        assert_eq!(out.arg0(), 0x1111_0001);
        assert_eq!(out.arg1(), 0x2222_0001);
        assert_eq!(out.arg2(), 1);
        assert_eq!(out.fuel_used(), 7);
    }

    #[test]
    fn mismatched_filter_returns_quiet_out() {
        let code = [
            ops::REQUIRE_INPUT_EQ,
            3,
            0xff,
            0xff,
            0xff,
            0xff,
            ops::EMIT,
            0,
            0,
            0,
            0,
            0,
        ];
        let mut bytes = [0u8; 64];
        let len = image(Target::Observe, &code, &mut bytes);
        let mut storage = EpfStorage::<1, 64>::new();
        let epf = Epf::new(&mut storage);

        epf.load(&bytes[..len]).expect("load");
        let out = epf.run(mismatch_event());

        assert!(!out.emitted());
        assert_eq!(out.fuel_used(), 1);
    }
}
