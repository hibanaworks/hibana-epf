use core::convert::TryInto;

use crate::{EVIDENCE_SCHEMA_HASH, Target, ops};

/// EPF image header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub abi: u16,
    pub target: Target,
    pub schema_hash: u32,
    pub code_len: u16,
    pub fuel_max: u16,
    pub mem_len: u16,
    pub code_hash: u32,
}

impl Header {
    pub const MAGIC: [u8; 4] = *b"EPF0";
    pub const ABI: u16 = 1;
    pub const SIZE: usize = 24;

    #[inline]
    pub const fn encode_into(self, out: &mut [u8; Self::SIZE]) {
        let (target_kind, policy_id) = self.target.encode();
        let abi = self.abi.to_le_bytes();
        let policy_id = policy_id.to_le_bytes();
        let code_len = self.code_len.to_le_bytes();
        let fuel_max = self.fuel_max.to_le_bytes();
        let mem_len = self.mem_len.to_le_bytes();
        let schema_hash = self.schema_hash.to_le_bytes();
        let code_hash = self.code_hash.to_le_bytes();

        out[0] = Self::MAGIC[0];
        out[1] = Self::MAGIC[1];
        out[2] = Self::MAGIC[2];
        out[3] = Self::MAGIC[3];
        out[4] = abi[0];
        out[5] = abi[1];
        out[6] = target_kind;
        out[7] = 0;
        out[8] = policy_id[0];
        out[9] = policy_id[1];
        out[10] = code_len[0];
        out[11] = code_len[1];
        out[12] = fuel_max[0];
        out[13] = fuel_max[1];
        out[14] = mem_len[0];
        out[15] = mem_len[1];
        out[16] = schema_hash[0];
        out[17] = schema_hash[1];
        out[18] = schema_hash[2];
        out[19] = schema_hash[3];
        out[20] = code_hash[0];
        out[21] = code_hash[1];
        out[22] = code_hash[2];
        out[23] = code_hash[3];
    }

    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, VerifyError> {
        if bytes.len() < Self::SIZE {
            return Err(VerifyError::TooShort);
        }
        if bytes[..4] != Self::MAGIC {
            return Err(VerifyError::BadMagic);
        }
        let abi = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
        let target_kind = bytes[6];
        let reserved = bytes[7];
        if reserved != 0 {
            return Err(VerifyError::ReservedByte { value: reserved });
        }
        let policy_id = u16::from_le_bytes(bytes[8..10].try_into().unwrap());
        let target = Target::decode(target_kind, policy_id)?;
        let header = Self {
            abi,
            target,
            code_len: u16::from_le_bytes(bytes[10..12].try_into().unwrap()),
            fuel_max: u16::from_le_bytes(bytes[12..14].try_into().unwrap()),
            mem_len: u16::from_le_bytes(bytes[14..16].try_into().unwrap()),
            schema_hash: u32::from_le_bytes(bytes[16..20].try_into().unwrap()),
            code_hash: u32::from_le_bytes(bytes[20..24].try_into().unwrap()),
        };
        header.validate()?;
        Ok(header)
    }

    pub(crate) fn validate(self) -> Result<(), VerifyError> {
        if self.abi != Self::ABI {
            return Err(VerifyError::UnsupportedAbi { abi: self.abi });
        }
        if self.schema_hash != EVIDENCE_SCHEMA_HASH {
            return Err(VerifyError::SchemaMismatch {
                expected: EVIDENCE_SCHEMA_HASH,
                found: self.schema_hash,
            });
        }
        if self.mem_len != 0 {
            return Err(VerifyError::UnsupportedMemory {
                bytes: self.mem_len,
            });
        }
        if self.fuel_max == 0 {
            return Err(VerifyError::ZeroFuel);
        }
        Ok(())
    }
}

/// Verified image view borrowed from caller memory.
#[derive(Clone, Copy, Debug)]
pub(crate) struct VerifiedImage<'a> {
    pub(crate) header: Header,
    _marker: core::marker::PhantomData<&'a [u8]>,
}

impl<'a> VerifiedImage<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Result<Self, VerifyError> {
        let header = Header::parse(bytes)?;
        let code_len = header.code_len as usize;
        let actual_len = bytes.len().saturating_sub(Header::SIZE);
        if actual_len != code_len {
            return Err(VerifyError::CodeLengthMismatch {
                declared: header.code_len,
                actual: actual_len,
            });
        }
        let code = &bytes[Header::SIZE..];
        let computed = compute_hash(code);
        if computed != header.code_hash {
            return Err(VerifyError::HashMismatch {
                expected: header.code_hash,
                computed,
            });
        }
        verify_code(code)?;
        Ok(Self {
            header,
            _marker: core::marker::PhantomData,
        })
    }
}

/// Verification failures raised while loading an EPF image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    TooShort,
    BadMagic,
    ReservedByte { value: u8 },
    UnsupportedAbi { abi: u16 },
    UnsupportedTarget { kind: u8, policy_id: u16 },
    SchemaMismatch { expected: u32, found: u32 },
    CodeLengthMismatch { declared: u16, actual: usize },
    HashMismatch { expected: u32, computed: u32 },
    ZeroFuel,
    UnknownOpcode { pc: usize, opcode: u8 },
    TruncatedInstruction { pc: usize },
    InvalidRegister { pc: usize, register: u8 },
    InvalidInputIndex { pc: usize, index: u8 },
    UnsupportedMemory { bytes: u16 },
}

fn verify_code(code: &[u8]) -> Result<(), VerifyError> {
    let mut pc = 0usize;
    while pc < code.len() {
        let op_pc = pc;
        let opcode = code[pc];
        pc += 1;
        match opcode {
            ops::LOAD_INPUT => {
                let reg = read_u8(code, &mut pc, op_pc)?;
                let input = read_u8(code, &mut pc, op_pc)?;
                require_register(op_pc, reg)?;
                if input > 3 {
                    return Err(VerifyError::InvalidInputIndex {
                        pc: op_pc,
                        index: input,
                    });
                }
            }
            ops::LOAD_IMM => {
                let reg = read_u8(code, &mut pc, op_pc)?;
                require_register(op_pc, reg)?;
                read_u32(code, &mut pc, op_pc)?;
            }
            ops::REQUIRE_INPUT_EQ => {
                let input = read_u8(code, &mut pc, op_pc)?;
                if input > 3 {
                    return Err(VerifyError::InvalidInputIndex {
                        pc: op_pc,
                        index: input,
                    });
                }
                read_u32(code, &mut pc, op_pc)?;
            }
            ops::REQUIRE_KIND => {
                read_u16(code, &mut pc, op_pc)?;
            }
            ops::REQUIRE_REASON => {
                read_u8(code, &mut pc, op_pc)?;
            }
            ops::LOAD_KIND | ops::LOAD_REASON => {
                let reg = read_u8(code, &mut pc, op_pc)?;
                require_register(op_pc, reg)?;
            }
            ops::EMIT => {
                let kind = read_u8(code, &mut pc, op_pc)?;
                let reason = read_u8(code, &mut pc, op_pc)?;
                let arg0 = read_u8(code, &mut pc, op_pc)?;
                let arg1 = read_u8(code, &mut pc, op_pc)?;
                let arg2 = read_u8(code, &mut pc, op_pc)?;
                require_register(op_pc, kind)?;
                require_register(op_pc, reason)?;
                require_register(op_pc, arg0)?;
                require_register(op_pc, arg1)?;
                require_register(op_pc, arg2)?;
            }
            ops::HALT => {}
            other => {
                return Err(VerifyError::UnknownOpcode {
                    pc: op_pc,
                    opcode: other,
                });
            }
        }
    }
    Ok(())
}

#[inline]
fn require_register(pc: usize, register: u8) -> Result<(), VerifyError> {
    if register > 7 {
        return Err(VerifyError::InvalidRegister { pc, register });
    }
    Ok(())
}

fn read_u8(code: &[u8], pc: &mut usize, op_pc: usize) -> Result<u8, VerifyError> {
    let Some(value) = code.get(*pc).copied() else {
        return Err(VerifyError::TruncatedInstruction { pc: op_pc });
    };
    *pc += 1;
    Ok(value)
}

fn read_u32(code: &[u8], pc: &mut usize, op_pc: usize) -> Result<u32, VerifyError> {
    let start = *pc;
    let end = start.saturating_add(4);
    let Some(bytes) = code.get(start..end) else {
        return Err(VerifyError::TruncatedInstruction { pc: op_pc });
    };
    *pc = end;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_u16(code: &[u8], pc: &mut usize, op_pc: usize) -> Result<u16, VerifyError> {
    let start = *pc;
    let end = start.saturating_add(2);
    let Some(bytes) = code.get(start..end) else {
        return Err(VerifyError::TruncatedInstruction { pc: op_pc });
    };
    *pc = end;
    Ok(u16::from_le_bytes(bytes.try_into().unwrap()))
}

/// Deterministic 32-bit FNV-1a hash used for image integrity.
pub fn compute_hash(bytes: &[u8]) -> u32 {
    const OFFSET: u32 = 0x811C_9DC5;
    const PRIME: u32 = 0x0100_0193;
    let mut hash = OFFSET;
    for byte in bytes {
        hash ^= *byte as u32;
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}
