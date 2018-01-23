use std::cmp;
use std::mem;
use std::ops::Deref;

use byteorder::ByteOrder;
use bytes::BufMut;
use failure::Error;

use framer::QuicFramer;
use frames::{PaddingBytes, QuicFrame, QuicPaddingFrame};
use packet::{QuicPacketHeader, QuicPacketPublicHeader};
use proto::{QuicConnectionId, QuicPacketNumber, QuicPacketNumberLength};
use types::{EncryptionLevel, QuicDiversificationNonce};

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
    /// Pending padding bytes to send.
    ///
    /// Pending padding bytes will be sent in next packet(s) (after all other frames)
    /// if current constructed packet does not have room to send all of them.
    pending_padding_bytes: PaddingBytes,
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
            pending_padding_bytes: PaddingBytes::default(),
        }
    }

    /// Serializes all frames which have been added and adds any which should be
    /// retransmitted to packet.retransmittable_frames.
    /// All frames must fit into a single packet.
    pub fn serialize_packet<E, B>(&mut self, buf: &mut B) -> Result<(), Error>
    where
        E: ByteOrder,
        B: BufMut + AsRef<[u8]>,
    {
        self.packet.packet_number += 1;

        let frames = mem::replace(&mut self.frames, vec![]);

        let packet_size = {
            let header = self.fill_packet_header();
            let header_size = header.size();

            let packet_size = self.framer.build_data_packet(&header, frames, buf)?;
            let buf = &buf.as_ref()[..packet_size];

            self.framer.encrypt_in_place(
                self.packet.encryption_level,
                self.packet.packet_number,
                &buf[..header_size],
                &buf[header_size..],
            )?;
        };

        self.maybe_add_padding()?;

        Ok(())
    }

    fn fill_packet_header(&self) -> QuicPacketHeader {
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

    fn bytes_free(&self) -> usize {
        0
    }

    fn maybe_add_padding(&mut self) -> Result<(), Error> {
        match self.pending_padding_bytes {
            PaddingBytes::Size(size) => {
                let num_padding_bytes = cmp::min(size, self.bytes_free());
                self.packet.padding_bytes = PaddingBytes::Size(num_padding_bytes);
                self.pending_padding_bytes = PaddingBytes::Size(size - num_padding_bytes);
            }
            PaddingBytes::Fill => {
                self.packet.padding_bytes = PaddingBytes::Fill;
            }
        }

        let padding_bytes = self.packet.padding_bytes;

        self.add_frame(QuicFrame::Padding(QuicPaddingFrame { padding_bytes }))
    }

    fn add_frame(&mut self, frame: QuicFrame<'a>) -> Result<(), Error> {
        self.frames.push(frame);

        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct SerializedPacket {
    packet_number: QuicPacketNumber,
    packet_number_length: QuicPacketNumberLength,
    encryption_level: EncryptionLevel,
    padding_bytes: PaddingBytes,
}
