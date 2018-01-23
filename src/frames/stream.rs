#![allow(non_upper_case_globals)]

use std::mem;

use byteorder::ByteOrder;
use bytes::BufMut;
use failure::{Error, Fail};
use nom::{self, IResult, Needed};

use constants::{kQuicFrameTypeStreamMask, kQuicFrameTypeStreamMask_Pre40};
use errors::QuicError::{self, IncompletePacket};
use framer::kQuicFrameTypeSize;
use frames::{QuicFrameReader, QuicFrameWriter, ReadFrame, WriteFrame};
use proto::{QuicStreamId, QuicStreamOffset};
use types::QuicVersion;

// Stream type format is 11FSSOOD.
// Stream frame relative shifts and masks for interpreting the stream flags.
// StreamID may be 1, 2, 3, or 4 bytes.
const kQuicStreamIdLengthNumBits_Pre40: usize = 2;
const kQuicStreamIdLengthShift_Pre40: usize = 0;
const kQuicStreamIdLengthNumBits: usize = 2;
const kQuicStreamIdLengthShift: usize = 3;

// Offset may be 0, 2, 4, or 8 bytes.
const kQuicStreamOffsetNumBits_Pre40: usize = 3;
const kQuicStreamOffsetShift_Pre40: usize = 2;
const kQuicStreamOffsetNumBits: usize = 2;
const kQuicStreamOffsetShift: usize = 1;

// Data length may be 0 or 2 bytes.
const kQuicStreamDataLengthShift_Pre40: usize = 5;
const kQuicStreamDataLengthShift: usize = 0;

// Fin bit may be set or not.
const kQuicStreamFinShift_Pre40: usize = 6;
const kQuicStreamFinShift: usize = 5;

/// The STREAM frame is used to both implicitly create a stream and to send data on it.
#[derive(Clone, Debug, PartialEq)]
pub struct QuicStreamFrame<'a> {
    /// A variable-sized unsigned ID unique to this stream.
    pub stream_id: QuicStreamId,
    /// A variable-sized unsigned number specifying the byte offset in the stream for this block of data.
    pub offset: QuicStreamOffset,
    /// the FIN bit indicates the sender is done sending on this stream and wishes to "half-close".
    pub fin: bool,
    /// An optional data in this stream frame.
    ///
    /// The option to omit the length should only be used when the packet is a "full-sized" Packet,
    /// to avoid the risk of corruption via padding.
    pub data: Option<&'a [u8]>,
}

impl<'a> ReadFrame<'a> for QuicStreamFrame<'a> {
    type Frame = QuicStreamFrame<'a>;
    type Error = Error;

    fn read_frame<E, R>(reader: &R, payload: &'a [u8]) -> Result<(QuicStreamFrame<'a>, &'a [u8]), Self::Error>
    where
        E: ByteOrder,
        R: QuicFrameReader<'a>,
    {
        Self::parse(reader.quic_version(), payload)
    }
}

impl<'a> WriteFrame<'a> for QuicStreamFrame<'a> {
    type Error = Error;

    fn frame_size<W>(&self, writer: &W) -> usize
    where
        W: QuicFrameWriter<'a>,
    {
        self.size(writer.quic_version())
    }

    fn write_frame<E, W, B>(&self, writer: &W, buf: &mut B) -> Result<usize, Self::Error>
    where
        E: ByteOrder,
        W: QuicFrameWriter<'a>,
        B: BufMut,
    {
        self.write_to::<E, B>(writer.quic_version(), buf)
    }
}

impl<'a> QuicStreamFrame<'a> {
    pub fn parse(quic_version: QuicVersion, payload: &'a [u8]) -> Result<(QuicStreamFrame<'a>, &'a [u8]), Error> {
        if let Some((&frame_type, remaining)) = payload.split_first() {
            let (stream_id_length, offset_length, has_data_length, fin) = if quic_version < QuicVersion::QUIC_VERSION_40
            {
                let flags = frame_type & !kQuicFrameTypeStreamMask_Pre40;
                (
                    1
                        + extract_bits!(
                            flags,
                            kQuicStreamIdLengthNumBits_Pre40,
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
                    1 + extract_bits!(flags, kQuicStreamIdLengthNumBits, kQuicStreamIdLengthShift) as usize,
                    match 1 << extract_bits!(flags, kQuicStreamOffsetNumBits, kQuicStreamOffsetShift) {
                        1 => 0,
                        n => n,
                    },
                    extract_bool!(flags, kQuicStreamDataLengthShift),
                    extract_bool!(flags, kQuicStreamFinShift),
                )
            };

            match parse_quic_stream_frame(
                remaining,
                quic_version,
                stream_id_length,
                offset_length,
                has_data_length,
            ) {
                IResult::Done(remaining, (stream_id, offset, data_len)) => {
                    let (data, remaining) = match data_len {
                        Some(len) if len > 0 => {
                            if len > remaining.len() {
                                bail!(IncompletePacket(nom::Needed::Size(len)).context("incomplete data frame."))
                            }

                            (Some(&remaining[..len]), &remaining[len..])
                        }
                        None if !remaining.is_empty() => (Some(remaining), &b""[..]),
                        _ => (None, remaining),
                    };

                    Ok((
                        QuicStreamFrame {
                            stream_id,
                            offset,
                            fin,
                            data,
                        },
                        remaining,
                    ))
                }
                IResult::Incomplete(needed) => bail!(IncompletePacket(needed).context("incomplete data frame.")),
                IResult::Error(err) => bail!(QuicError::from(err).context("unable to process data frame.")),
            }
        } else {
            bail!(IncompletePacket(Needed::Size(1)).context("incomplete data frame."))
        }
    }

    fn size(&self, quic_version: QuicVersion) -> usize {
        // Frame Type
        kQuicFrameTypeSize +
        // Stream ID
        stream_id_size(self.stream_id) +
        // Offset
        stream_offset_size(quic_version, self.offset) +
        // Data
        self.data
            .as_ref()
            .map_or(0, |data| mem::size_of::<u16>() + data.len())
    }

    fn write_to<E, T>(&self, quic_version: QuicVersion, buf: &mut T) -> Result<usize, Error>
    where
        E: ByteOrder,
        T: BufMut,
    {
        let frame_size = self.size(quic_version);

        if buf.remaining_mut() < frame_size {
            bail!(QuicError::NotEnoughBuffer(frame_size))
        }

        let stream_id_size = stream_id_size(self.stream_id);
        let stream_offset_size = stream_offset_size(quic_version, self.offset);
        let mut flags;

        if quic_version < QuicVersion::QUIC_VERSION_40 {
            flags = kQuicFrameTypeStreamMask_Pre40;

            set_bits!(
                flags,
                stream_id_size as u8 - 1,
                kQuicStreamIdLengthShift_Pre40
            );
            if stream_offset_size > 0 {
                set_bits!(
                    flags,
                    stream_offset_size as u8 - 1,
                    kQuicStreamOffsetShift_Pre40
                );
            }
            set_bool!(
                flags,
                self.data.map_or(false, |v| !v.is_empty()),
                kQuicStreamDataLengthShift_Pre40
            );
            set_bool!(flags, self.fin, kQuicStreamFinShift_Pre40);
        } else {
            flags = kQuicFrameTypeStreamMask;

            set_bits!(flags, stream_id_size as u8 - 1, kQuicStreamIdLengthShift);
            set_bits!(
                flags,
                stream_offset_size.next_power_of_two().trailing_zeros() as u8,
                kQuicStreamOffsetShift
            );
            set_bool!(
                flags,
                self.data.map_or(false, |v| !v.is_empty()),
                kQuicStreamDataLengthShift
            );
            set_bool!(flags, self.fin, kQuicStreamFinShift);
        }

        // Frame Type
        buf.put_u8(flags);
        // Data length
        if quic_version > QuicVersion::QUIC_VERSION_39 {
            if let Some(data) = self.data {
                buf.put_u16::<E>(data.len() as u16);
            }
        }
        // Stream ID
        buf.put_uint::<E>(u64::from(self.stream_id), stream_id_size);
        // Offset
        buf.put_uint::<E>(self.offset, stream_offset_size);
        // Data length
        if quic_version <= QuicVersion::QUIC_VERSION_39 {
            if let Some(data) = self.data {
                buf.put_u16::<E>(data.len() as u16);
            }
        }
        // Data
        if let Some(data) = self.data {
            buf.put_slice(data);
        }

        Ok(frame_size)
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

fn stream_id_size(stream_id: QuicStreamId) -> usize {
    (1..4).find(|n| stream_id >> (8 * n) == 0).unwrap_or(4)
}

fn stream_offset_size(quic_verion: QuicVersion, stream_offset: QuicStreamOffset) -> usize {
    if quic_verion < QuicVersion::QUIC_VERSION_40 {
        if stream_offset == 0 {
            0
        } else {
            (2..8).find(|n| stream_offset >> (8 * n) == 0).unwrap_or(8)
        }
    } else {
        (0..3)
            .map(|n| n * 2)
            .find(|n| stream_offset >> (8 * n) == 0)
            .unwrap_or(8)
    }
}

#[cfg(test)]
mod tests {
    use frames::mocks;

    use super::*;

    const kStreamId: QuicStreamId = 0x01020304;
    const kStreamOffset: QuicStreamOffset = 0xBA98FEDC32107654;

    #[test]
    fn stream_frame() {
        #[cfg_attr(rustfmt, rustfmt_skip)]
        const test_cases: &[(QuicVersion, &[u8])] = &[
            (
                QuicVersion::QUIC_VERSION_38,
                &[
                    // frame type (stream frame with fin)
                    0xFF,
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
                ],
            ),
            (
                QuicVersion::QUIC_VERSION_39,
                &[
                    // frame type (stream frame with fin)
                    0xFF,
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
                ],
            ),
            (
                QuicVersion::QUIC_VERSION_40,
                &[
                    // frame type (stream frame with fin)
                    0xFF,
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
                ],
            ),
        ];

        let stream_frame = QuicStreamFrame {
            stream_id: kStreamId,
            offset: kStreamOffset,
            fin: true,
            data: Some(&b"hello world!"[..]),
        };

        for &(quic_version, payload) in test_cases {
            let (reader, writer) = mocks::pair(quic_version);

            assert_eq!(stream_frame.frame_size(&writer), payload.len());
            assert_eq!(
                reader.read_frame::<QuicStreamFrame>(payload).unwrap(),
                (stream_frame.clone(), &[][..]),
                "parse stream frame, version {:?}",
                quic_version,
            );

            let mut buf = Vec::with_capacity(payload.len());

            assert_eq!(
                writer.write_frame(&stream_frame, &mut buf).unwrap(),
                buf.len()
            );
            assert_eq!(
                &buf,
                &payload,
                "write stream frame {:?}, version {:?}",
                stream_frame,
                quic_version
            );
        }
    }
}
