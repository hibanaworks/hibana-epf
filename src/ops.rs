//! Pico-class EPF bytecode opcodes.

pub(crate) const LOAD_INPUT: u8 = 0x10;
pub(crate) const LOAD_IMM: u8 = 0x11;
pub(crate) const REQUIRE_INPUT_EQ: u8 = 0x12;
pub(crate) const LOAD_KIND: u8 = 0x13;
pub(crate) const LOAD_REASON: u8 = 0x14;
pub(crate) const REQUIRE_KIND: u8 = 0x15;
pub(crate) const REQUIRE_REASON: u8 = 0x16;
pub(crate) const EMIT: u8 = 0x20;
pub(crate) const HALT: u8 = 0xff;
