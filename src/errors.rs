use nom::{self, IError, Needed};

use tag::QuicTag;

#[derive(Debug, Fail)]
pub enum QuicError {
    #[fail(display = "incomlete packet")] IncompletePacket(Needed),

    #[fail(display = "invalid packet, {}", _0)] InvalidPacket(#[cause] nom::Err),

    #[fail(display = "unsupported version: {:?}", _0)] UnsupportedVersion(QuicTag),

    #[fail(display = "parameter not found: {:?}", _0)] ParamNotFound(QuicTag),

    #[fail(display = "invalid parameter: {:?}", _0)] InvalidParam(QuicTag),
}

impl From<IError> for QuicError {
    fn from(error: IError) -> QuicError {
        match error {
            IError::Error(err) => QuicError::InvalidPacket(err),
            IError::Incomplete(needed) => QuicError::IncompletePacket(needed),
        }
    }
}
