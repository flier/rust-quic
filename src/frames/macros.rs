use num::FromPrimitive;

use errors::QuicErrorCode;

#[macro_export]
macro_rules! extract_bits {
    ($flags:expr, $bits:expr, $offset:expr) => {
        ($flags >> $offset) & ((1 << $bits) - 1)
    };
}

#[macro_export]
macro_rules! extract_bool {
    ($flags:expr, $offset:expr) => {
        0 != extract_bits!($flags, 1, $offset)
    };
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
