use std::cmp;
use std::mem;
use std::ops::Deref;

use byteorder::ByteOrder;
use bytes::{BufMut, Bytes};
use failure::Error;

use errors::QuicError;
use framer::{FrameWriter, QuicFramer, kQuicStreamPayloadLengthSize};
use frames::{PaddingBytes, QuicFrame, WriteFrame};
use packet::{QuicPacketHeader, QuicPacketPublicHeader};
use proto::{QuicConnectionId, QuicPacketNumber, QuicPacketNumberLength};
use types::{EncryptionLevel, QuicDiversificationNonce, QuicFrameType};

pub struct QuicPacketCreator<'a, T, V>
where
    T: 'a + Deref<Target = V>,
    V: 'a,
{
    connection_id: QuicConnectionId,
    framer: &'a QuicFramer<'a, T, V>,

    // Packet used to invoke `on_serialized_packet`.
    packet: SerializedPacket,

    /// Frames to be added to the next SerializedPacket
    frames: Vec<QuicFrame<'a>>,

    diversification_nonce: Option<&'a QuicDiversificationNonce>,

    /// Maximum length including headers and encryption (UDP payload length.)
    max_packet_length: usize,
    max_plaintext_size: usize,

    /// packet_size should never be read directly, use `packet_size()` instead.
    packet_size: usize,

    /// Pending padding bytes to send.
    ///
    /// Pending padding bytes will be sent in next packet(s) (after all other frames)
    /// if current constructed packet does not have room to send all of them.
    pending_padding_bytes: Option<PaddingBytes>,
}

impl<'a, T, V> QuicPacketCreator<'a, T, V>
where
    T: Deref<Target = V>,
    V: ,
{
    pub fn new(connection_id: QuicConnectionId, framer: &'a QuicFramer<'a, T, V>) -> Self {
        QuicPacketCreator {
            connection_id,
            framer,
            packet: SerializedPacket::default(),
            frames: vec![],
            diversification_nonce: None,
            max_packet_length: 0,
            max_plaintext_size: 0,
            packet_size: 0,
            pending_padding_bytes: None,
        }
    }

    pub fn set_max_packet_length(&mut self, len: usize) {
        self.max_packet_length = len;
        self.max_plaintext_size = self.framer.max_plaintext_size(len);
    }

    /// Serializes all frames which have been added and adds any which should be
    /// retransmitted to packet.retransmittable_frames.
    /// All frames must fit into a single packet.
    pub fn serialize_packet<E, B>(&mut self, buf: &mut B) -> Result<(), Error>
    where
        E: ByteOrder,
        B: BufMut + AsRef<[u8]>,
    {
        self.maybe_add_padding()?;

        let frames = mem::replace(&mut self.frames, vec![]);

        let (associated_data, plain_text) = {
            self.packet.packet_number += 1;

            let header = self.packet_header();
            let header_size = header.size();
            let packet_size = self.framer.build_data_packet(&header, frames, buf)?;
            let buf = &buf.as_ref()[..packet_size];

            (&buf[..header_size], &buf[header_size..])
        };

        self.packet.encrypted_payload = Some(self.framer.encrypt_payload(
            self.packet.encryption_level,
            self.packet.packet_number,
            associated_data,
            plain_text,
        )?);

        self.packet_size = 0;

        Ok(())
    }

    fn packet_header(&self) -> QuicPacketHeader {
        QuicPacketHeader {
            public_header: QuicPacketPublicHeader {
                reset_flag: false,
                connection_id: Some(self.connection_id),
                packet_number_length: self.packet.packet_number_length,
                versions: None,
                nonce: self.nonce_in_public_header(),
            },
            packet_number: self.packet.packet_number,
        }
    }

    fn nonce_in_public_header(&self) -> Option<&QuicDiversificationNonce> {
        if self.packet.encryption_level == EncryptionLevel::Initial {
            self.diversification_nonce
        } else {
            None
        }
    }

    fn maybe_add_padding(&mut self) -> Result<(), Error> {
        // The current packet should have no padding bytes because padding is only
        // added when this method is called just before the packet is serialized.
        debug_assert!(self.packet.padding_bytes.is_none());

        if self.bytes_free() == 0 {
            // Don't pad full packets.
            Ok(())
        } else {
            self.packet.padding_bytes = match self.pending_padding_bytes {
                Some(PaddingBytes::Size(size)) if size > 0 => {
                    let num_padding_bytes = cmp::min(size, self.bytes_free());
                    self.pending_padding_bytes = Some(PaddingBytes::Size(size - num_padding_bytes));

                    Some(PaddingBytes::Size(num_padding_bytes))
                }
                Some(PaddingBytes::Fill) => Some(PaddingBytes::Fill),
                _ => None, // Do not need padding.
            };

            if let Some(padding_bytes) = self.packet.padding_bytes {
                self.add_frame(QuicFrame::padding(padding_bytes))
            } else {
                Ok(())
            }
        }
    }

    /// Returns the number of bytes which are available to be used by additional frames in the packet.
    /// Since stream frames are slightly smaller when they are the last frame in a packet,
    /// this method will return a different value than max_packet_size - packet_size, in this case.
    fn bytes_free(&self) -> usize {
        debug_assert!(self.max_plaintext_size >= self.packet_size());

        self.max_plaintext_size
            - cmp::min(
                self.max_plaintext_size,
                self.packet_size() + self.expandsion_on_new_frame(),
            )
    }

    /// Returns the number of bytes that the packet will expand by if a new frame is added to the packet.
    /// If the last frame was a stream frame, it will expand slightly when a new frame is added,
    /// and this method returns the amount of expected expansion.
    fn expandsion_on_new_frame(&self) -> usize {
        // If the last frame in the packet is a stream frame,
        // then it will expand to include the stream_length field when a new frame is added.
        let has_trailing_stream_frame = self.frames
            .last()
            .map_or(false, |frame| frame.frame_type() == QuicFrameType::Stream);

        if has_trailing_stream_frame {
            kQuicStreamPayloadLengthSize
        } else {
            0
        }
    }

    /// Returns the number of bytes in the current packet, including the header,
    /// if serialized with the current frames.
    /// Adding a frame to the packet may change the serialized length of existing frames,
    /// as per the comment in BytesFree.
    fn packet_size(&self) -> usize {
        if self.frames.is_empty() {
            self.packet_header().size()
        } else {
            self.packet_size
        }
    }

    fn add_frame(&mut self, frame: QuicFrame<'a>) -> Result<(), Error> {
        let frame_size = self.expandsion_on_new_frame() + {
            let header = self.packet_header();
            let writer = FrameWriter::new(self.framer, &header);

            frame.frame_size(&writer)
        };

        let frame_len = self.framer.serialized_frame_length(
            &frame,
            self.bytes_free(),
            self.frames.is_empty(),
            frame_size,
        );

        if frame_len == 0 {
            self.flush()?;

            bail!(QuicError::PacketTooLarge(self.packet_size + frame_size));
        }

        self.packet_size = self.expandsion_on_new_frame() + frame_len;

        self.frames.push(frame);

        Ok(())
    }

    fn flush(&self) -> Result<(), Error> {
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct SerializedPacket {
    packet_number: QuicPacketNumber,
    packet_number_length: QuicPacketNumberLength,
    encryption_level: EncryptionLevel,
    padding_bytes: Option<PaddingBytes>,
    encrypted_payload: Option<Bytes>,
}
