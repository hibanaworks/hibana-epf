use hibana::substrate::{
    Lane, SessionId,
    cap::advanced::{
        CAP_HANDLE_LEN, CapError, CapsMask, ControlHandling, ControlMint, ControlScopeKind, ScopeId,
    },
    cap::{CapShot, ControlResourceKind, ResourceKind},
};

pub(crate) const LABEL_POLICY_LOAD: u8 = 210;
pub(crate) const LABEL_POLICY_ACTIVATE: u8 = 211;
pub(crate) const LABEL_POLICY_REVERT: u8 = 212;
pub(crate) const LABEL_POLICY_ANNOTATE: u8 = 213;

// Mirrors the core fence-authorized lifecycle mask until the substrate exposes
// a public effect-specific mask constructor.
const FENCE_MASK_BITS: u16 = 1 << 7;

#[inline]
const fn fence_caps() -> CapsMask {
    CapsMask::from_bits(FENCE_MASK_BITS)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyLoadKind;

impl ResourceKind for PolicyLoadKind {
    type Handle = (u32, u16);
    const TAG: u8 = 0x4A;
    const NAME: &'static str = "PolicyLoad";
    const AUTO_MINT_EXTERNAL: bool = false;

    fn encode_handle(handle: &Self::Handle) -> [u8; CAP_HANDLE_LEN] {
        let mut buf = [0u8; CAP_HANDLE_LEN];
        buf[0..4].copy_from_slice(&handle.0.to_le_bytes());
        buf[4..6].copy_from_slice(&handle.1.to_le_bytes());
        buf
    }

    fn decode_handle(data: [u8; CAP_HANDLE_LEN]) -> Result<Self::Handle, CapError> {
        Ok((
            u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            u16::from_le_bytes([data[4], data[5]]),
        ))
    }

    fn zeroize(_handle: &mut Self::Handle) {}

    fn caps_mask(_handle: &Self::Handle) -> CapsMask {
        fence_caps()
    }

    fn scope_id(_handle: &Self::Handle) -> Option<ScopeId> {
        None
    }
}

impl ControlMint for PolicyLoadKind {
    fn mint_handle(sid: SessionId, lane: Lane, _scope: ScopeId) -> Self::Handle {
        (sid.raw(), lane.raw() as u16)
    }
}

impl ControlResourceKind for PolicyLoadKind {
    const LABEL: u8 = LABEL_POLICY_LOAD;
    const SCOPE: ControlScopeKind = ControlScopeKind::Policy;
    const TAP_ID: u16 = 0;
    const SHOT: CapShot = CapShot::One;
    const HANDLING: ControlHandling = ControlHandling::Canonical;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyActivateKind;

impl ResourceKind for PolicyActivateKind {
    type Handle = (u32, u16);
    const TAG: u8 = 0x4B;
    const NAME: &'static str = "PolicyActivate";
    const AUTO_MINT_EXTERNAL: bool = false;

    fn encode_handle(handle: &Self::Handle) -> [u8; CAP_HANDLE_LEN] {
        PolicyLoadKind::encode_handle(handle)
    }

    fn decode_handle(data: [u8; CAP_HANDLE_LEN]) -> Result<Self::Handle, CapError> {
        PolicyLoadKind::decode_handle(data)
    }

    fn zeroize(_handle: &mut Self::Handle) {}

    fn caps_mask(_handle: &Self::Handle) -> CapsMask {
        fence_caps()
    }

    fn scope_id(_handle: &Self::Handle) -> Option<ScopeId> {
        None
    }
}

impl ControlMint for PolicyActivateKind {
    fn mint_handle(sid: SessionId, lane: Lane, _scope: ScopeId) -> Self::Handle {
        (sid.raw(), lane.raw() as u16)
    }
}

impl ControlResourceKind for PolicyActivateKind {
    const LABEL: u8 = LABEL_POLICY_ACTIVATE;
    const SCOPE: ControlScopeKind = ControlScopeKind::Policy;
    const TAP_ID: u16 = 0;
    const SHOT: CapShot = CapShot::One;
    const HANDLING: ControlHandling = ControlHandling::Canonical;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyRevertKind;

impl ResourceKind for PolicyRevertKind {
    type Handle = (u32, u16);
    const TAG: u8 = 0x4C;
    const NAME: &'static str = "PolicyRevert";
    const AUTO_MINT_EXTERNAL: bool = false;

    fn encode_handle(handle: &Self::Handle) -> [u8; CAP_HANDLE_LEN] {
        PolicyLoadKind::encode_handle(handle)
    }

    fn decode_handle(data: [u8; CAP_HANDLE_LEN]) -> Result<Self::Handle, CapError> {
        PolicyLoadKind::decode_handle(data)
    }

    fn zeroize(_handle: &mut Self::Handle) {}

    fn caps_mask(_handle: &Self::Handle) -> CapsMask {
        fence_caps()
    }

    fn scope_id(_handle: &Self::Handle) -> Option<ScopeId> {
        None
    }
}

impl ControlMint for PolicyRevertKind {
    fn mint_handle(sid: SessionId, lane: Lane, _scope: ScopeId) -> Self::Handle {
        (sid.raw(), lane.raw() as u16)
    }
}

impl ControlResourceKind for PolicyRevertKind {
    const LABEL: u8 = LABEL_POLICY_REVERT;
    const SCOPE: ControlScopeKind = ControlScopeKind::Policy;
    const TAP_ID: u16 = 0;
    const SHOT: CapShot = CapShot::One;
    const HANDLING: ControlHandling = ControlHandling::Canonical;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyAnnotateKind;

impl ResourceKind for PolicyAnnotateKind {
    type Handle = (u32, u32);
    const TAG: u8 = 0x4D;
    const NAME: &'static str = "PolicyAnnotate";
    const AUTO_MINT_EXTERNAL: bool = false;

    fn encode_handle(handle: &Self::Handle) -> [u8; CAP_HANDLE_LEN] {
        let mut buf = [0u8; CAP_HANDLE_LEN];
        buf[0..3].copy_from_slice(&handle.0.to_le_bytes()[0..3]);
        buf[3..6].copy_from_slice(&handle.1.to_le_bytes()[0..3]);
        buf
    }

    fn decode_handle(data: [u8; CAP_HANDLE_LEN]) -> Result<Self::Handle, CapError> {
        Ok((
            u32::from_le_bytes([data[0], data[1], data[2], 0]),
            u32::from_le_bytes([data[3], data[4], data[5], 0]),
        ))
    }

    fn zeroize(_handle: &mut Self::Handle) {}

    fn caps_mask(_handle: &Self::Handle) -> CapsMask {
        fence_caps()
    }

    fn scope_id(_handle: &Self::Handle) -> Option<ScopeId> {
        None
    }
}

impl ControlMint for PolicyAnnotateKind {
    fn mint_handle(_sid: SessionId, _lane: Lane, _scope: ScopeId) -> Self::Handle {
        (0, 0)
    }
}

impl ControlResourceKind for PolicyAnnotateKind {
    const LABEL: u8 = LABEL_POLICY_ANNOTATE;
    const SCOPE: ControlScopeKind = ControlScopeKind::Policy;
    const TAP_ID: u16 = 0;
    const SHOT: CapShot = CapShot::One;
    const HANDLING: ControlHandling = ControlHandling::Canonical;
}
