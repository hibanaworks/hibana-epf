use core::convert::TryInto;

use super::{Slot, ops, slot_contract, vm::REG_COUNT};

/// VM header as laid out in bytecode (after the four-byte magic).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub code_len: u16,
    pub fuel_max: u16,
    pub mem_len: u16,
    pub hash: u32,
}

impl Header {
    pub const MAGIC: [u8; 4] = *b"K1VM";
    pub const SIZE: usize = 4 + 2 + 2 + 2 + 2 + 4;

    pub const fn max_mem_len() -> usize {
        1024
    }

    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, VerifyError> {
        if bytes.len() < Self::SIZE {
            return Err(VerifyError::TooShort);
        }
        if bytes[..4] != Self::MAGIC {
            return Err(VerifyError::BadMagic);
        }
        let code_len = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
        let fuel_max = u16::from_le_bytes(bytes[6..8].try_into().unwrap());
        let mem_len = u16::from_le_bytes(bytes[8..10].try_into().unwrap());
        let flags = u16::from_le_bytes(bytes[10..12].try_into().unwrap());
        if flags != 0 {
            return Err(VerifyError::UnsupportedFlags { flags });
        }
        let hash = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
        let header = Self {
            code_len,
            fuel_max,
            mem_len,
            hash,
        };
        header.validate()?;
        Ok(header)
    }

    #[cfg(test)]
    pub(crate) fn encode_into(&self, buf: &mut [u8; Self::SIZE]) {
        buf[..4].copy_from_slice(&Self::MAGIC);
        buf[4..6].copy_from_slice(&self.code_len.to_le_bytes());
        buf[6..8].copy_from_slice(&self.fuel_max.to_le_bytes());
        buf[8..10].copy_from_slice(&self.mem_len.to_le_bytes());
        buf[10..12].copy_from_slice(&0u16.to_le_bytes());
        buf[12..16].copy_from_slice(&self.hash.to_le_bytes());
    }

    pub(crate) fn validate(&self) -> Result<(), VerifyError> {
        if self.mem_len as usize > Self::max_mem_len() {
            return Err(VerifyError::MemTooLarge {
                requested: self.mem_len,
            });
        }
        if self.fuel_max == 0 {
            return Err(VerifyError::ZeroFuel);
        }
        Ok(())
    }
}

/// Verification failures raised while loading a bytecode image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    TooShort,
    BadMagic,
    CodeLengthMismatch { declared: u16, actual: usize },
    CodeTooLarge { declared: u16 },
    MemTooLarge { requested: u16 },
    HashMismatch { expected: u32, computed: u32 },
    ZeroFuel,
    UnsupportedFlags { flags: u16 },
    UnknownOpcode { pc: usize, opcode: u8 },
    TruncatedInstruction { pc: usize },
    InvalidInputIndex { pc: usize, index: u8 },
    InvalidRegister { pc: usize, register: u8 },
    InvalidJumpTarget { pc: usize, target: u16 },
    InputForbiddenForSlot { pc: usize, slot: Slot },
    MemOpsForbiddenForSlot { pc: usize, slot: Slot },
}

/// Fully verified bytecode image (header + code slice).
#[derive(Clone, Copy)]
pub struct VerifiedImage<'a> {
    pub(crate) header: Header,
    pub(crate) code: &'a [u8],
}

impl<'a> core::fmt::Debug for VerifiedImage<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VerifiedImage")
            .field("header", &self.header)
            .field("code_len", &self.code.len())
            .finish()
    }
}

impl<'a> VerifiedImage<'a> {
    pub const MAX_CODE_LEN: usize = 2048;

    pub fn new_for_slot(bytes: &'a [u8], slot: Slot) -> Result<Self, VerifyError> {
        Self::new_inner(bytes, slot)
    }

    pub(crate) fn from_parts_for_slot(
        header: Header,
        code: &'a [u8],
        slot: Slot,
    ) -> Result<Self, VerifyError> {
        Self::from_parts_inner(header, code, slot)
    }

    fn new_inner(bytes: &'a [u8], slot: Slot) -> Result<Self, VerifyError> {
        if bytes.len() < Header::SIZE {
            return Err(VerifyError::TooShort);
        }
        let header = Header::parse(bytes)?;
        let code_len = header.code_len as usize;
        if code_len > Self::MAX_CODE_LEN {
            return Err(VerifyError::CodeTooLarge {
                declared: header.code_len,
            });
        }
        let remaining = bytes.len().saturating_sub(Header::SIZE);
        if remaining != code_len {
            return Err(VerifyError::CodeLengthMismatch {
                declared: header.code_len,
                actual: remaining,
            });
        }
        let code = &bytes[Header::SIZE..];
        let hash = compute_hash(code);
        if hash != header.hash {
            return Err(VerifyError::HashMismatch {
                expected: header.hash,
                computed: hash,
            });
        }
        verify_epf_input_operands(code, slot)?;
        Ok(Self { header, code })
    }

    fn from_parts_inner(header: Header, code: &'a [u8], slot: Slot) -> Result<Self, VerifyError> {
        header.validate()?;
        if header.code_len as usize > Self::MAX_CODE_LEN {
            return Err(VerifyError::CodeTooLarge {
                declared: header.code_len,
            });
        }
        if code.len() != header.code_len as usize {
            return Err(VerifyError::CodeLengthMismatch {
                declared: header.code_len,
                actual: code.len(),
            });
        }
        let hash = compute_hash(code);
        if hash != header.hash {
            return Err(VerifyError::HashMismatch {
                expected: header.hash,
                computed: hash,
            });
        }
        verify_epf_input_operands(code, slot)?;
        Ok(Self { header, code })
    }

    pub(crate) fn confirm_slot(self, slot: Slot) -> Result<Self, VerifyError> {
        verify_epf_input_operands(self.code, slot)?;
        Ok(self)
    }
}

fn operand_len(opcode: u8) -> Option<usize> {
    Some(match opcode {
        ops::instr::NOP | ops::instr::HALT => 0,
        ops::instr::LOAD_IMM => 5,
        ops::instr::JUMP => 2,
        ops::instr::JUMP_Z => 3,
        ops::instr::JUMP_GT => 4,
        ops::instr::LOAD_MEM | ops::instr::STORE_MEM => 2,
        ops::instr::GET_LATENCY
        | ops::instr::GET_QUEUE
        | ops::instr::GET_CONGESTION
        | ops::instr::GET_RETRY
        | ops::instr::GET_SCOPE_RANGE
        | ops::instr::GET_SCOPE_NEST
        | ops::instr::GET_EVENT_ID
        | ops::instr::GET_EVENT_ARG0
        | ops::instr::GET_EVENT_ARG1
        | ops::instr::ACT_ROUTE
        | ops::instr::ACT_DEFER => 1,
        ops::instr::GET_INPUT => 2,
        ops::instr::SHR | ops::instr::AND | ops::instr::AND_IMM => 3,
        ops::instr::JUMP_EQ_IMM => 4,
        ops::instr::ACT_ABORT => 2,
        ops::instr::ACT_ANNOT => 3,
        ops::instr::TAP_OUT => 4,
        _ => return None,
    })
}

#[inline]
fn read_u16_le(lo: u8, hi: u8) -> u16 {
    (lo as u16) | ((hi as u16) << 8)
}

fn is_instruction_boundary(code: &[u8], target: usize) -> bool {
    if target >= code.len() {
        return false;
    }

    let mut pc = 0usize;
    while pc < code.len() {
        if pc == target {
            return true;
        }
        let Some(len) = operand_len(code[pc]) else {
            return false;
        };
        let next = pc.saturating_add(1).saturating_add(len);
        if next > code.len() {
            return false;
        }
        pc = next;
    }
    false
}

#[inline]
fn require_register(pc: usize, register: u8) -> Result<(), VerifyError> {
    if register as usize >= REG_COUNT {
        return Err(VerifyError::InvalidRegister { pc, register });
    }
    Ok(())
}

#[inline]
fn require_jump_target(code: &[u8], pc: usize, target: u16) -> Result<(), VerifyError> {
    if !is_instruction_boundary(code, target as usize) {
        return Err(VerifyError::InvalidJumpTarget { pc, target });
    }
    Ok(())
}

fn verify_epf_input_operands(code: &[u8], slot: Slot) -> Result<(), VerifyError> {
    let mut pc = 0usize;
    while pc < code.len() {
        let op_pc = pc;
        let opcode = code[pc];
        pc += 1;
        let operand_len =
            operand_len(opcode).ok_or(VerifyError::UnknownOpcode { pc: op_pc, opcode })?;
        if pc + operand_len > code.len() {
            return Err(VerifyError::TruncatedInstruction { pc: op_pc });
        }
        let operands = &code[pc..pc + operand_len];

        match opcode {
            ops::instr::LOAD_IMM => {
                require_register(op_pc, operands[0])?;
            }
            ops::instr::JUMP => {
                require_jump_target(code, op_pc, read_u16_le(operands[0], operands[1]))?;
            }
            ops::instr::JUMP_Z => {
                require_register(op_pc, operands[0])?;
                require_jump_target(code, op_pc, read_u16_le(operands[1], operands[2]))?;
            }
            ops::instr::JUMP_GT => {
                require_register(op_pc, operands[0])?;
                require_register(op_pc, operands[1])?;
                require_jump_target(code, op_pc, read_u16_le(operands[2], operands[3]))?;
            }
            ops::instr::LOAD_MEM | ops::instr::STORE_MEM => {
                require_register(op_pc, operands[0])?;
                require_register(op_pc, operands[1])?;
            }
            ops::instr::GET_LATENCY
            | ops::instr::GET_QUEUE
            | ops::instr::GET_CONGESTION
            | ops::instr::GET_RETRY
            | ops::instr::GET_SCOPE_RANGE
            | ops::instr::GET_SCOPE_NEST
            | ops::instr::GET_EVENT_ID
            | ops::instr::GET_EVENT_ARG0
            | ops::instr::GET_EVENT_ARG1
            | ops::instr::ACT_ROUTE
            | ops::instr::ACT_DEFER => {
                require_register(op_pc, operands[0])?;
            }
            ops::instr::GET_INPUT => {
                require_register(op_pc, operands[0])?;
            }
            ops::instr::SHR | ops::instr::AND | ops::instr::AND_IMM => {
                require_register(op_pc, operands[0])?;
                require_register(op_pc, operands[1])?;
                if opcode == ops::instr::AND {
                    require_register(op_pc, operands[2])?;
                }
            }
            ops::instr::JUMP_EQ_IMM => {
                require_register(op_pc, operands[0])?;
                require_jump_target(code, op_pc, read_u16_le(operands[2], operands[3]))?;
            }
            ops::instr::ACT_ANNOT => {
                require_register(op_pc, operands[2])?;
            }
            ops::instr::TAP_OUT => {
                require_register(op_pc, operands[2])?;
                require_register(op_pc, operands[3])?;
            }
            ops::instr::NOP | ops::instr::HALT | ops::instr::ACT_ABORT => {}
            _ => unreachable!("operand_len filters unknown opcodes"),
        }

        if matches!(opcode, ops::instr::LOAD_MEM | ops::instr::STORE_MEM)
            && !slot_contract::slot_allows_mem_ops(slot)
        {
            return Err(VerifyError::MemOpsForbiddenForSlot { pc: op_pc, slot });
        }
        if opcode == ops::instr::GET_INPUT {
            let index = operands[1];
            if index > 3 {
                return Err(VerifyError::InvalidInputIndex { pc: op_pc, index });
            }
            if !slot_contract::slot_allows_get_input(slot) {
                return Err(VerifyError::InputForbiddenForSlot { pc: op_pc, slot });
            }
        }
        pc += operand_len;
    }
    Ok(())
}

/// Deterministic 32-bit hash (FNV-1a) used for bytecode integrity.
pub fn compute_hash(code: &[u8]) -> u32 {
    const OFFSET: u32 = 0x811C_9DC5;
    const PRIME: u32 = 0x0100_0193;
    let mut hash = OFFSET;
    for byte in code {
        hash ^= *byte as u32;
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops;

    #[test]
    fn verify_roundtrip() {
        let code = [ops::instr::NOP, ops::instr::HALT];
        let mut image = [0u8; Header::SIZE + 2];
        let hash = compute_hash(&code);
        let header = Header {
            code_len: code.len() as u16,
            fuel_max: 16,
            mem_len: 32,
            hash,
        };
        header.encode_into((&mut image[..Header::SIZE]).try_into().unwrap());
        image[Header::SIZE..].copy_from_slice(&code);

        let verified = VerifiedImage::new_for_slot(&image, Slot::Route).expect("must verify");
        assert_eq!(verified.header.fuel_max, 16);
        assert_eq!(verified.code, code);
    }

    #[test]
    fn reject_unknown_opcode() {
        let code = [0x30u8, 0x00, 0x00];
        let mut image = [0u8; Header::SIZE + 3];
        let header = Header {
            code_len: code.len() as u16,
            fuel_max: 8,
            mem_len: 32,
            hash: compute_hash(&code),
        };
        header.encode_into((&mut image[..Header::SIZE]).try_into().unwrap());
        image[Header::SIZE..].copy_from_slice(&code);
        assert!(matches!(
            VerifiedImage::new_for_slot(&image, Slot::Route).unwrap_err(),
            VerifyError::UnknownOpcode {
                pc: 0,
                opcode: 0x30
            }
        ));
    }

    #[test]
    fn reject_bad_magic() {
        let mut bytes = [0u8; Header::SIZE];
        bytes[..4].copy_from_slice(b"BAD!");
        assert!(matches!(
            VerifiedImage::new_for_slot(&bytes, Slot::Route).unwrap_err(),
            VerifyError::BadMagic
        ));
    }

    #[test]
    fn reject_reserved_header_flags() {
        let code = [ops::instr::NOP, ops::instr::HALT];
        let mut image = [0u8; Header::SIZE + 2];
        let header = Header {
            code_len: code.len() as u16,
            fuel_max: 8,
            mem_len: 32,
            hash: compute_hash(&code),
        };
        header.encode_into((&mut image[..Header::SIZE]).try_into().unwrap());
        image[10] = 1;
        image[Header::SIZE..].copy_from_slice(&code);
        assert_eq!(
            VerifiedImage::new_for_slot(&image, Slot::Route).unwrap_err(),
            VerifyError::UnsupportedFlags { flags: 1 }
        );
    }

    #[test]
    fn reject_hash_mismatch() {
        let mut image = [0u8; Header::SIZE + 2];
        let header = Header {
            code_len: 2,
            fuel_max: 8,
            mem_len: 32,
            hash: 0xDEAD_BEEF,
        };
        header.encode_into((&mut image[..Header::SIZE]).try_into().unwrap());
        image[Header::SIZE..].copy_from_slice(&[1, 2]);
        assert!(matches!(
            VerifiedImage::new_for_slot(&image, Slot::Route).unwrap_err(),
            VerifyError::HashMismatch { .. }
        ));
    }

    #[test]
    fn verify_get_input_index_ok() {
        let code = [ops::instr::GET_INPUT, 0x00, 0x03, ops::instr::HALT];
        let mut image = [0u8; Header::SIZE + 4];
        let header = Header {
            code_len: code.len() as u16,
            fuel_max: 8,
            mem_len: 32,
            hash: compute_hash(&code),
        };
        header.encode_into((&mut image[..Header::SIZE]).try_into().unwrap());
        image[Header::SIZE..].copy_from_slice(&code);
        let verified = VerifiedImage::new_for_slot(&image, Slot::Route).expect("must verify");
        assert_eq!(verified.code, code);
    }

    #[test]
    fn reject_get_input_index_out_of_range() {
        let code = [ops::instr::GET_INPUT, 0x00, 0x04, ops::instr::HALT];
        let mut image = [0u8; Header::SIZE + 4];
        let header = Header {
            code_len: code.len() as u16,
            fuel_max: 8,
            mem_len: 32,
            hash: compute_hash(&code),
        };
        header.encode_into((&mut image[..Header::SIZE]).try_into().unwrap());
        image[Header::SIZE..].copy_from_slice(&code);
        assert!(matches!(
            VerifiedImage::new_for_slot(&image, Slot::Route).unwrap_err(),
            VerifyError::InvalidInputIndex { index: 4, .. }
        ));
    }

    #[test]
    fn reject_truncated_get_input_instruction() {
        let code = [ops::instr::GET_INPUT, 0x00];
        let mut image = [0u8; Header::SIZE + 2];
        let header = Header {
            code_len: code.len() as u16,
            fuel_max: 8,
            mem_len: 32,
            hash: compute_hash(&code),
        };
        header.encode_into((&mut image[..Header::SIZE]).try_into().unwrap());
        image[Header::SIZE..].copy_from_slice(&code);
        assert!(matches!(
            VerifiedImage::new_for_slot(&image, Slot::Route).unwrap_err(),
            VerifyError::TruncatedInstruction { .. }
        ));
    }

    #[test]
    fn reject_get_input_for_forward_slot() {
        let code = [ops::instr::GET_INPUT, 0x00, 0x01, ops::instr::HALT];
        let mut image = [0u8; Header::SIZE + 4];
        let header = Header {
            code_len: code.len() as u16,
            fuel_max: 8,
            mem_len: 32,
            hash: compute_hash(&code),
        };
        header.encode_into((&mut image[..Header::SIZE]).try_into().unwrap());
        image[Header::SIZE..].copy_from_slice(&code);
        assert!(matches!(
            VerifiedImage::new_for_slot(&image, Slot::Forward).unwrap_err(),
            VerifyError::InputForbiddenForSlot {
                slot: Slot::Forward,
                ..
            }
        ));
    }

    #[test]
    fn reject_get_input_for_rendezvous_slot() {
        let code = [ops::instr::GET_INPUT, 0x00, 0x01, ops::instr::HALT];
        let mut image = [0u8; Header::SIZE + 4];
        let header = Header {
            code_len: code.len() as u16,
            fuel_max: 8,
            mem_len: 32,
            hash: compute_hash(&code),
        };
        header.encode_into((&mut image[..Header::SIZE]).try_into().unwrap());
        image[Header::SIZE..].copy_from_slice(&code);
        assert!(matches!(
            VerifiedImage::new_for_slot(&image, Slot::Rendezvous).unwrap_err(),
            VerifyError::InputForbiddenForSlot {
                slot: Slot::Rendezvous,
                ..
            }
        ));
    }

    #[test]
    fn allow_get_input_for_route_slot() {
        let code = [ops::instr::GET_INPUT, 0x00, 0x01, ops::instr::HALT];
        let mut image = [0u8; Header::SIZE + 4];
        let header = Header {
            code_len: code.len() as u16,
            fuel_max: 8,
            mem_len: 32,
            hash: compute_hash(&code),
        };
        header.encode_into((&mut image[..Header::SIZE]).try_into().unwrap());
        image[Header::SIZE..].copy_from_slice(&code);
        let verified = VerifiedImage::new_for_slot(&image, Slot::Route).expect("must verify");
        assert_eq!(verified.code, code);
    }

    #[test]
    fn route_slot_forbids_mem_ops() {
        let code = [
            ops::instr::LOAD_IMM,
            0x00,
            0x01,
            0x00,
            0x00,
            0x00,
            ops::instr::STORE_MEM,
            0x00,
            0x00,
            ops::instr::HALT,
        ];
        let mut image = [0u8; Header::SIZE + 10];
        let header = Header {
            code_len: code.len() as u16,
            fuel_max: 16,
            mem_len: 32,
            hash: compute_hash(&code),
        };
        header.encode_into((&mut image[..Header::SIZE]).try_into().unwrap());
        image[Header::SIZE..].copy_from_slice(&code);
        assert!(matches!(
            VerifiedImage::new_for_slot(&image, Slot::Route).unwrap_err(),
            VerifyError::MemOpsForbiddenForSlot {
                slot: Slot::Route,
                ..
            }
        ));
    }

    #[test]
    fn allow_act_defer_operand() {
        let code = [ops::instr::ACT_DEFER, 0x00];
        let mut image = [0u8; Header::SIZE + 2];
        let header = Header {
            code_len: code.len() as u16,
            fuel_max: 8,
            mem_len: 32,
            hash: compute_hash(&code),
        };
        header.encode_into((&mut image[..Header::SIZE]).try_into().unwrap());
        image[Header::SIZE..].copy_from_slice(&code);
        let verified = VerifiedImage::new_for_slot(&image, Slot::Route).expect("must verify");
        assert_eq!(verified.code, code);
    }

    #[test]
    fn reject_register_operand_out_of_range() {
        let code = [ops::instr::LOAD_IMM, 0x08, 0x01, 0x00, 0x00, 0x00];
        let mut image = [0u8; Header::SIZE + 6];
        let header = Header {
            code_len: code.len() as u16,
            fuel_max: 8,
            mem_len: 32,
            hash: compute_hash(&code),
        };
        header.encode_into((&mut image[..Header::SIZE]).try_into().unwrap());
        image[Header::SIZE..].copy_from_slice(&code);
        assert!(matches!(
            VerifiedImage::new_for_slot(&image, Slot::Route).unwrap_err(),
            VerifyError::InvalidRegister { pc: 0, register: 8 }
        ));
    }

    #[test]
    fn reject_jump_target_inside_operand() {
        let code = [ops::instr::JUMP, 0x02, 0x00, ops::instr::HALT];
        let mut image = [0u8; Header::SIZE + 4];
        let header = Header {
            code_len: code.len() as u16,
            fuel_max: 8,
            mem_len: 32,
            hash: compute_hash(&code),
        };
        header.encode_into((&mut image[..Header::SIZE]).try_into().unwrap());
        image[Header::SIZE..].copy_from_slice(&code);
        assert!(matches!(
            VerifiedImage::new_for_slot(&image, Slot::Route).unwrap_err(),
            VerifyError::InvalidJumpTarget { pc: 0, target: 2 }
        ));
    }
}
