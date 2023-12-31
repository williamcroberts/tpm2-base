#![allow(dead_code)]
use crate::Tss2Rc;

pub const TSS2_RC_LAYER_SHIFT: u32 = 16;
pub const TSS2_RC_LAYER_MASK: Tss2Rc = 0xFF << TSS2_RC_LAYER_SHIFT;
pub const TSS2_MU_RC_LAYER: Tss2Rc = 9 << TSS2_RC_LAYER_SHIFT;

pub const TSS2_BASE_RC_GENERAL_FAILURE: Tss2Rc = 1;
pub const TSS2_BASE_RC_NOT_IMPLEMENTED: Tss2Rc = 2;
pub const TSS2_BASE_RC_BAD_CONTEXT: Tss2Rc = 3;
pub const TSS2_BASE_RC_ABI_MISMATCH: Tss2Rc = 4;
pub const TSS2_BASE_RC_BAD_REFERENCE: Tss2Rc = 5;
pub const TSS2_BASE_RC_INSUFFICIENT_BUFFER: Tss2Rc = 6;
pub const TSS2_BASE_RC_BAD_SEQUENCE: Tss2Rc = 7;
pub const TSS2_BASE_RC_NO_CONNECTION: Tss2Rc = 8;
pub const TSS2_BASE_RC_TRY_AGAIN: Tss2Rc = 9;
pub const TSS2_BASE_RC_IO_ERROR: Tss2Rc = 10;
pub const TSS2_BASE_RC_BAD_VALUE: Tss2Rc = 11;
pub const TSS2_BASE_RC_NOT_PERMITTED: Tss2Rc = 12;
pub const TSS2_BASE_RC_INVALID_SESSIONS: Tss2Rc = 13;
pub const TSS2_BASE_RC_NO_DECRYPT_PARAM: Tss2Rc = 14;
pub const TSS2_BASE_RC_NO_ENCRYPT_PARAM: Tss2Rc = 15;
pub const TSS2_BASE_RC_BAD_SIZE: Tss2Rc = 16;
pub const TSS2_BASE_RC_MALFORMED_RESPONSE: Tss2Rc = 17;
pub const TSS2_BASE_RC_INSUFFICIENT_CONTEXT: Tss2Rc = 18;
pub const TSS2_BASE_RC_INSUFFICIENT_RESPONSE: Tss2Rc = 19;

pub const TSS2_MU_RC_INSUFFICIENT_BUFFER: Tss2Rc =
    TSS2_MU_RC_LAYER | TSS2_BASE_RC_INSUFFICIENT_BUFFER;
pub const TSS2_MU_RC_BAD_SIZE: Tss2Rc = TSS2_MU_RC_LAYER | TSS2_BASE_RC_BAD_SIZE;
