#![allow(non_upper_case_globals)]

use std::borrow::Cow;

use failure::{Error, Fail};
use nom::{self, IResult};

use errors::QuicError;
use frames::{kQuicFrameTypeStreamMask, kQuicFrameTypeStreamMask_Pre40};
use types::{QuicStreamId, QuicStreamOffset, QuicVersion};

// Stream type format is 11FSSOOD.
// Stream frame relative shifts and masks for interpreting the stream flags.
// StreamID may be 1, 2, 3, or 4 bytes.
const kQuicStreamIdLengthShift_Pre40: usize = 0;
const kQuicStreamIDLengthNumBits_Pre40: usize = 2;
const kQuicStreamIDLengthShift: usize = 3;
const kQuicStreamIDLengthNumBits: usize = 2;

// Offset may be 0, 2, 4, or 8 bytes.
const kQuicStreamOffsetNumBits_Pre40: usize = 3;
const kQuicStreamOffsetShift_Pre40: usize = 3;
const kQuicStreamOffsetNumBits: usize = 2;
const kQuicStreamOffsetShift: usize = 1;

// Data length may be 0 or 2 bytes.
const kQuicStreamDataLengthShift_Pre40: usize = 5;
const kQuicStreamDataLengthShift: usize = 0;

// Fin bit may be set or not.
const kQuicStreamFinShift_Pre40: usize = 6;
const kQuicStreamFinShift: usize = 5;

#[derive(Clone, Debug, PartialEq)]
pub struct QuicStreamFrame<'a> {
    pub stream_id: QuicStreamId,
    pub offset: QuicStreamOffset, // Location of this data in the stream.
    pub fin: bool,
    pub data: Cow<'a, [u8]>,
}

impl<'a> QuicStreamFrame<'a> {
    pub fn parse(quic_version: QuicVersion, frame_type: u8, payload: &'a [u8]) -> Result<QuicStreamFrame<'a>, Error> {
        let (stream_id_length, offset_length, has_data_length, fin) = if quic_version < QuicVersion::QUIC_VERSION_40 {
            let flags = frame_type & !kQuicFrameTypeStreamMask_Pre40;
            (
                1
                    + extract_bits!(
                        flags,
                        kQuicStreamIDLengthNumBits_Pre40,
                        kQuicStreamIdLengthShift_Pre40
                    ) as usize,
                match extract_bits!(
                    flags,
                    kQuicStreamOffsetNumBits_Pre40,
                    kQuicStreamOffsetShift_Pre40
                ) {
                    0 => 0,
                    n => n as usize + 1, // There is no encoding for 1 byte, only 0 and 2 through 8.
                },
                extract_bool!(flags, kQuicStreamDataLengthShift_Pre40),
                extract_bool!(flags, kQuicStreamFinShift_Pre40),
            )
        } else {
            let flags = frame_type & !kQuicFrameTypeStreamMask;
            (
                1 + extract_bits!(flags, kQuicStreamIDLengthNumBits, kQuicStreamIDLengthShift) as usize,
                match 1 << extract_bits!(flags, kQuicStreamOffsetNumBits, kQuicStreamOffsetShift) {
                    1 => 0,
                    n => n,
                },
                extract_bool!(flags, kQuicStreamDataLengthShift),
                extract_bool!(flags, kQuicStreamFinShift),
            )
        };

        match parse_quic_stream_frame(
            payload,
            quic_version,
            stream_id_length,
            offset_length,
            has_data_length,
        ) {
            IResult::Done(remaining, (stream_id, offset, data_len)) => Ok(QuicStreamFrame {
                stream_id,
                offset,
                fin,
                data: if let Some(len) = data_len {
                    if len > remaining.len() {
                        bail!(QuicError::IncompletePacket(nom::Needed::Size(len)).context("incomplete data frame."))
                    } else {
                        let data = &remaining[..len];

                        data.into()
                    }
                } else {
                    remaining.into()
                },
            }),
            IResult::Incomplete(needed) => bail!(QuicError::IncompletePacket(needed).context("incomplete data frame.")),
            IResult::Error(err) => bail!(QuicError::InvalidPacket(err).context("unable to process data frame.")),
        }
    }
}

named_args!(
    parse_quic_stream_frame(quic_version: QuicVersion,
                            stream_id_length: usize,
                            offset_length: usize,
                            has_data_length: bool)<(QuicStreamId, QuicStreamOffset, Option<usize>)>,
        do_parse!(
            data_len_new: cond!(has_data_length && quic_version > QuicVersion::QUIC_VERSION_39,
                                u16!(quic_version.endianness())) >>
            stream_id: uint!(quic_version.endianness(), stream_id_length) >>
            offset: uint!(quic_version.endianness(), offset_length) >>
            data_len_pre40: cond!(has_data_length && quic_version <= QuicVersion::QUIC_VERSION_39,
                                  u16!(quic_version.endianness())) >>
            data_len: value!(data_len_new.or(data_len_pre40)) >>
        (
            (
                stream_id as QuicStreamId,
                offset as QuicStreamOffset,
                data_len.map(|n| n as usize),
            )
        )
    )
);

#[cfg(test)]
mod tests {
    use super::*;

    const kStreamId: QuicStreamId = 0x01020304;
    const kStreamOffset: QuicStreamOffset = 0xBA98FEDC32107654;

    #[test]
    fn parse_frame() {
        const packet: &[u8] = &[
            // stream id
            0x04, 0x03, 0x02, 0x01,
            // offset
            0x54, 0x76, 0x10, 0x32,
            0xDC, 0xFE, 0x98, 0xBA,
            // data length
            0x0c, 0x00,
            // data
            b'h',  b'e',  b'l',  b'l',
            b'o',  b' ',  b'w',  b'o',
            b'r',  b'l',  b'd',  b'!',
            // paddings
            0x00, 0x00,
        ];

        const packet39: &[u8] = &[
            // stream id
            0x01, 0x02, 0x03, 0x04,
            // offset
            0xBA, 0x98, 0xFE, 0xDC,
            0x32, 0x10, 0x76, 0x54,
            // data length
            0x00, 0x0c,
            // data
            b'h',  b'e',  b'l',  b'l',
            b'o',  b' ',  b'w',  b'o',
            b'r',  b'l',  b'd',  b'!',
            // paddings
            0x00, 0x00,
        ];

        const packet40: &[u8] = &[
            // data length
            0x00, 0x0c,
            // stream id
            0x01, 0x02, 0x03, 0x04,
            // offset
            0xBA, 0x98, 0xFE, 0xDC,
            0x32, 0x10, 0x76, 0x54,
            // data
            b'h',  b'e',  b'l',  b'l',
            b'o',  b' ',  b'w',  b'o',
            b'r',  b'l',  b'd',  b'!',
            // paddings
            0x00, 0x00,
        ];

        let stream_frame = QuicStreamFrame {
            stream_id: kStreamId,
            offset: kStreamOffset,
            fin: true,
            data: Cow::from(&b"hello world!"[..]),
        };

        assert_eq!(
            QuicStreamFrame::parse(QuicVersion::QUIC_VERSION_38, 0xFF, packet).unwrap(),
            stream_frame
        );
        assert_eq!(
            QuicStreamFrame::parse(QuicVersion::QUIC_VERSION_39, 0xFF, packet39).unwrap(),
            stream_frame
        );
        assert_eq!(
            QuicStreamFrame::parse(QuicVersion::QUIC_VERSION_40, 0xFF, packet40).unwrap(),
            stream_frame
        );
    }
}
