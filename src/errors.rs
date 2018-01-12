#![allow(non_snake_case)]

use extprim::u128::u128;
use nom::{self, IError};
use num::FromPrimitive;

use types::QuicTag;

#[derive(Debug, Fail, PartialEq)]
pub enum QuicError {
    #[fail(display = "incomlete packet")] IncompletePacket(nom::Needed),

    #[fail(display = "invalid packet, {}", _0)] InvalidPacket(#[cause] nom::Err),

    #[fail(display = "invalid packet header, {}", _0)] InvalidPacketHeader(String),

    #[fail(display = "invalid reset packet, {}", _0)] InvalidResetPacket(String),

    #[fail(display = "packet too large, {}", _0)] PacketTooLarge(usize),

    #[fail(display = "packet hash mismatch, {:x}", _0)] PacketHashMismatch(u128),

    #[fail(display = "unsupported version, {:?}", _0)] UnsupportedVersion(QuicTag),

    #[fail(display = "parameter not found, {:?}", _0)] ParamNotFound(QuicTag),

    #[fail(display = "invalid parameter, {:?}", _0)] InvalidParam(QuicTag),

    #[fail(display = "invalid frame type, {}", _0)] InvalidFrameType(u8),

    #[fail(display = "nonce length mismatch, {}", _0)] NonceLenMismatch(usize),

    #[fail(display = "duplicate tag, {}", _0)] DuplicateTag(QuicTag),

    #[fail(display = "tags {} out of order", _0)] TagOutOfOrder(QuicTag),

    #[fail(display = "offset {} out of order", _0)] OffsetOutOfOrder(usize),

    #[fail(display = "underflow with ack block length")] AckBlockOverflow,
}

impl From<IError> for QuicError {
    fn from(error: IError) -> QuicError {
        match error {
            IError::Error(err) => QuicError::InvalidPacket(err),
            IError::Incomplete(needed) => QuicError::IncompletePacket(needed),
        }
    }
}

impl From<nom::Needed> for QuicError {
    fn from(needed: nom::Needed) -> Self {
        QuicError::IncompletePacket(needed)
    }
}

impl From<nom::ErrorKind> for QuicError {
    fn from(err: nom::ErrorKind) -> Self {
        match err {
            nom::ErrorKind::Custom(code) => match ParseError::from_u32(code) {
                Some(ParseError::AckBlockOverflow) => QuicError::AckBlockOverflow,
                None => QuicError::InvalidPacket(err),
            },
            _ => QuicError::InvalidPacket(err),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, FromPrimitive, PartialEq)]
pub enum ParseError {
    AckBlockOverflow,
}
