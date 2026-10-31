use crate::{Out, Target, ops};

pub(crate) const REG_COUNT: usize = 8;

/// Trap reasons emitted by the Pico-class EPF VM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trap {
    FuelExhausted,
    IllegalOpcode(u8),
    VerifyFailed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct VmInput {
    pub(crate) kind: u16,
    pub(crate) reason: u8,
    pub(crate) words: [u32; 4],
}

pub(crate) fn run(target: Target, epoch: u32, code: &[u8], input: VmInput, fuel_max: u16) -> Out {
    let mut regs = [0u32; REG_COUNT];
    let mut pc = 0usize;
    let mut fuel_used = 0u16;

    loop {
        if fuel_used == fuel_max {
            return Out::trap(target, epoch, Trap::FuelExhausted, fuel_used);
        }

        let Some(opcode) = read_u8(code, &mut pc) else {
            return Out::trap(target, epoch, Trap::VerifyFailed, fuel_used);
        };
        fuel_used = fuel_used.saturating_add(1);

        match opcode {
            ops::LOAD_INPUT => {
                let Some(reg) = read_reg(code, &mut pc) else {
                    return Out::trap(target, epoch, Trap::VerifyFailed, fuel_used);
                };
                let Some(input_idx) = read_u8(code, &mut pc) else {
                    return Out::trap(target, epoch, Trap::VerifyFailed, fuel_used);
                };
                let Some(value) = input.words.get(input_idx as usize).copied() else {
                    return Out::trap(target, epoch, Trap::VerifyFailed, fuel_used);
                };
                regs[reg] = value;
            }
            ops::LOAD_IMM => {
                let Some(reg) = read_reg(code, &mut pc) else {
                    return Out::trap(target, epoch, Trap::VerifyFailed, fuel_used);
                };
                let Some(imm) = read_u32(code, &mut pc) else {
                    return Out::trap(target, epoch, Trap::VerifyFailed, fuel_used);
                };
                regs[reg] = imm;
            }
            ops::REQUIRE_INPUT_EQ => {
                let Some(input_idx) = read_u8(code, &mut pc) else {
                    return Out::trap(target, epoch, Trap::VerifyFailed, fuel_used);
                };
                let Some(expected) = read_u32(code, &mut pc) else {
                    return Out::trap(target, epoch, Trap::VerifyFailed, fuel_used);
                };
                let Some(value) = input.words.get(input_idx as usize).copied() else {
                    return Out::trap(target, epoch, Trap::VerifyFailed, fuel_used);
                };
                if value != expected {
                    return Out::quiet(target, epoch, fuel_used);
                }
            }
            ops::REQUIRE_KIND => {
                let Some(expected) = read_u16(code, &mut pc) else {
                    return Out::trap(target, epoch, Trap::VerifyFailed, fuel_used);
                };
                if input.kind != expected {
                    return Out::quiet(target, epoch, fuel_used);
                }
            }
            ops::REQUIRE_REASON => {
                let Some(expected) = read_u8(code, &mut pc) else {
                    return Out::trap(target, epoch, Trap::VerifyFailed, fuel_used);
                };
                if input.reason != expected {
                    return Out::quiet(target, epoch, fuel_used);
                }
            }
            ops::LOAD_KIND => {
                let Some(reg) = read_reg(code, &mut pc) else {
                    return Out::trap(target, epoch, Trap::VerifyFailed, fuel_used);
                };
                regs[reg] = input.kind as u32;
            }
            ops::LOAD_REASON => {
                let Some(reg) = read_reg(code, &mut pc) else {
                    return Out::trap(target, epoch, Trap::VerifyFailed, fuel_used);
                };
                regs[reg] = input.reason as u32;
            }
            ops::EMIT => {
                let Some(kind) = read_reg(code, &mut pc) else {
                    return Out::trap(target, epoch, Trap::VerifyFailed, fuel_used);
                };
                let Some(reason) = read_reg(code, &mut pc) else {
                    return Out::trap(target, epoch, Trap::VerifyFailed, fuel_used);
                };
                let Some(arg0) = read_reg(code, &mut pc) else {
                    return Out::trap(target, epoch, Trap::VerifyFailed, fuel_used);
                };
                let Some(arg1) = read_reg(code, &mut pc) else {
                    return Out::trap(target, epoch, Trap::VerifyFailed, fuel_used);
                };
                let Some(arg2) = read_reg(code, &mut pc) else {
                    return Out::trap(target, epoch, Trap::VerifyFailed, fuel_used);
                };
                return Out::emit(
                    (target, epoch),
                    [regs[kind], regs[reason], regs[arg0], regs[arg1], regs[arg2]],
                    fuel_used,
                );
            }
            ops::HALT => return Out::quiet(target, epoch, fuel_used),
            other => return Out::trap(target, epoch, Trap::IllegalOpcode(other), fuel_used),
        }
    }
}

fn read_u8(code: &[u8], pc: &mut usize) -> Option<u8> {
    let value = code.get(*pc).copied()?;
    *pc += 1;
    Some(value)
}

fn read_u32(code: &[u8], pc: &mut usize) -> Option<u32> {
    let b0 = read_u8(code, pc)? as u32;
    let b1 = read_u8(code, pc)? as u32;
    let b2 = read_u8(code, pc)? as u32;
    let b3 = read_u8(code, pc)? as u32;
    Some(b0 | (b1 << 8) | (b2 << 16) | (b3 << 24))
}

fn read_u16(code: &[u8], pc: &mut usize) -> Option<u16> {
    let b0 = read_u8(code, pc)? as u16;
    let b1 = read_u8(code, pc)? as u16;
    Some(b0 | (b1 << 8))
}

fn read_reg(code: &[u8], pc: &mut usize) -> Option<usize> {
    let reg = read_u8(code, pc)? as usize;
    if reg < REG_COUNT { Some(reg) } else { None }
}
