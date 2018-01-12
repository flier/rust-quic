#![allow(non_snake_case)]

use extprim::u128::u128;
use nom;
use num::FromPrimitive;

use types::QuicTag;

#[derive(Debug, Fail, PartialEq)]
pub enum QuicError {
    #[fail(display = "incomlete packet")] IncompletePacket(nom::Needed),

    #[fail(display = "invalid packet, {:?}", _0)] InvalidPacket(nom::ErrorKind),

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

    #[fail(display = "underflow with first ack block length")] FirstAckBlockLengthOverflow,

    #[fail(display = "underflow with ack block length")] AckBlockLengthOverflow,
}

impl<I> From<nom::IError<I>> for QuicError {
    fn from(err: nom::IError<I>) -> Self {
        match err {
            nom::IError::Error(err) => QuicError::from(err.into_error_kind()),
            nom::IError::Incomplete(needed) => QuicError::from(needed),
        }
    }
}

impl<P> From<nom::Err<P>> for QuicError {
    fn from(err: nom::Err<P>) -> Self {
        QuicError::InvalidPacket(err.into_error_kind())
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
                Some(ParseError::FirstAckBlockLengthOverflow) => QuicError::FirstAckBlockLengthOverflow,
                Some(ParseError::AckBlockLengthOverflow) => QuicError::AckBlockLengthOverflow,
                None => QuicError::InvalidPacket(err),
            },
            _ => QuicError::InvalidPacket(err),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, FromPrimitive, PartialEq)]
pub enum ParseError {
    FirstAckBlockLengthOverflow,
    AckBlockLengthOverflow,
}
