use nom::be_u8;
use num::FromPrimitive;

use errors::QuicErrorCode;
use types::QuicFrameType;

#[macro_export]
macro_rules! extract_bits {
    ($flags:expr, $bits:expr, $shift:expr) => {
        ($flags >> $shift) & ((1 << $bits) - 1)
    };
}

#[macro_export]
macro_rules! extract_bool {
    ($flags:expr, $shift:expr) => {
        0 != extract_bits!($flags, 1, $shift)
    };
}

#[macro_export]
macro_rules! set_bits {
    ($flags:expr, $bits:expr, $shift:expr) => {
        $flags |= ($bits) << ($shift)
    };
}

#[macro_export]
macro_rules! set_bool {
    ($flags:expr, $bit:expr, $shift:expr) => {
        if $bit {
            $flags |= 1 << ($shift)
        } else {
            $flags &= !(1 << ($shift))
        }
    };
}

named_args!(
    pub frame_type(frame_type: QuicFrameType)<u8>,
        verify!(be_u8, |b| b == frame_type as u8)
);

#[macro_export]
macro_rules! frame_type {
    ($input:expr, $ty:expr) => {
        $crate::frames::macros::frame_type($input, $ty)
    }
}

named_args!(
    pub error_code(endianness: ::nom::Endianness)<QuicErrorCode>, map!(u32!(endianness), |code| {
        QuicErrorCode::from_u32(code).unwrap_or(QuicErrorCode::QUIC_LAST_ERROR)
    })
);

#[macro_export]
macro_rules! error_code {
    ($input:expr, $endianness:expr) => (
        $crate::frames::macros::error_code($input, $endianness)
    )
}

named_args!(
    pub string_piece16(endianness: ::nom::Endianness)<Option<&str>>, do_parse!(
        len: u16!(endianness) >>
        s: cond!(len > 0, take_str!(len)) >>
        (
            s
        )
    )
);

#[macro_export]
macro_rules! string_piece16 {
    ($input:expr, $endianness:expr) => (
        $crate::frames::macros::string_piece16($input, $endianness)
    )
}

#[macro_export]
macro_rules! uint (
    ($input:expr, $endianness:expr, $nbytes:expr) => (
        if $nbytes < 1 || $nbytes > 8 {
            ::nom::IResult::Error(::nom::Err::Code(::nom::ErrorKind::Tag))
        } else if $input.len() < $nbytes {
            ::nom::IResult::Incomplete(::nom::Needed::Size($nbytes))
        } else {
            use byteorder::ByteOrder;

            let (remaining, value) = match $endianness {
                ::nom::Endianness::Little => (
                    &$input[$nbytes..], ::byteorder::LittleEndian::read_uint($input, $nbytes)
                ),
                ::nom::Endianness::Big => (
                    &$input[$nbytes..], ::byteorder::BigEndian::read_uint($input, $nbytes)
                ),
            };

            ::nom::IResult::Done(remaining, value)
        }
    );
);
