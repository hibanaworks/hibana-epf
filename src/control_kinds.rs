use hibana::substrate::{
    Lane, SessionId,
    cap::advanced::{CAP_HANDLE_LEN, CapError, ControlOp, ControlPath, ControlScopeKind, ScopeId},
    cap::{CapShot, ControlResourceKind, ResourceKind},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyLoadKind;

impl ResourceKind for PolicyLoadKind {
    type Handle = (u32, u16);
    const TAG: u8 = 0x4A;
    const NAME: &'static str = "PolicyLoad";

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
}

impl ControlResourceKind for PolicyLoadKind {
    const LABEL: u8 = 106;
    const SCOPE: ControlScopeKind = ControlScopeKind::Policy;
    const PATH: ControlPath = ControlPath::Local;
    const TAP_ID: u16 = 0;
    const SHOT: CapShot = CapShot::One;
    const OP: ControlOp = ControlOp::Fence;
    const AUTO_MINT_WIRE: bool = false;

    fn mint_handle(session: SessionId, lane: Lane, _scope: ScopeId) -> Self::Handle {
        (session.raw(), lane.raw() as u16)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyActivateKind;

impl ResourceKind for PolicyActivateKind {
    type Handle = (u32, u16);
    const TAG: u8 = 0x4B;
    const NAME: &'static str = "PolicyActivate";

    fn encode_handle(handle: &Self::Handle) -> [u8; CAP_HANDLE_LEN] {
        PolicyLoadKind::encode_handle(handle)
    }

    fn decode_handle(data: [u8; CAP_HANDLE_LEN]) -> Result<Self::Handle, CapError> {
        PolicyLoadKind::decode_handle(data)
    }

    fn zeroize(_handle: &mut Self::Handle) {}
}

impl ControlResourceKind for PolicyActivateKind {
    const LABEL: u8 = 107;
    const SCOPE: ControlScopeKind = ControlScopeKind::Policy;
    const PATH: ControlPath = ControlPath::Local;
    const TAP_ID: u16 = 0;
    const SHOT: CapShot = CapShot::One;
    const OP: ControlOp = ControlOp::TxCommit;
    const AUTO_MINT_WIRE: bool = false;

    fn mint_handle(session: SessionId, lane: Lane, _scope: ScopeId) -> Self::Handle {
        (session.raw(), lane.raw() as u16)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyRevertKind;

impl ResourceKind for PolicyRevertKind {
    type Handle = (u32, u16);
    const TAG: u8 = 0x4C;
    const NAME: &'static str = "PolicyRevert";

    fn encode_handle(handle: &Self::Handle) -> [u8; CAP_HANDLE_LEN] {
        PolicyLoadKind::encode_handle(handle)
    }

    fn decode_handle(data: [u8; CAP_HANDLE_LEN]) -> Result<Self::Handle, CapError> {
        PolicyLoadKind::decode_handle(data)
    }

    fn zeroize(_handle: &mut Self::Handle) {}
}

impl ControlResourceKind for PolicyRevertKind {
    const LABEL: u8 = 108;
    const SCOPE: ControlScopeKind = ControlScopeKind::Policy;
    const PATH: ControlPath = ControlPath::Local;
    const TAP_ID: u16 = 0;
    const SHOT: CapShot = CapShot::One;
    const OP: ControlOp = ControlOp::TxAbort;
    const AUTO_MINT_WIRE: bool = false;

    fn mint_handle(session: SessionId, lane: Lane, _scope: ScopeId) -> Self::Handle {
        (session.raw(), lane.raw() as u16)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyAnnotateKind;

impl ResourceKind for PolicyAnnotateKind {
    type Handle = (u32, u32);
    const TAG: u8 = 0x4D;
    const NAME: &'static str = "PolicyAnnotate";

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
}

impl ControlResourceKind for PolicyAnnotateKind {
    const LABEL: u8 = 109;
    const SCOPE: ControlScopeKind = ControlScopeKind::Policy;
    const PATH: ControlPath = ControlPath::Local;
    const TAP_ID: u16 = 0;
    const SHOT: CapShot = CapShot::One;
    const OP: ControlOp = ControlOp::Fence;
    const AUTO_MINT_WIRE: bool = false;

    fn mint_handle(_session: SessionId, _lane: Lane, _scope: ScopeId) -> Self::Handle {
        (0, 0)
    }
}
