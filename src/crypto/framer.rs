use failure::Error;

use crypto::CryptoHandshakeMessage;
use types::Perspective;

/// `CryptoFramerVisitor` visit the decrypted message.
pub trait CryptoFramerVisitor {
    /// Called when a complete handshake message has been parsed.
    fn on_handshake_message(&self, message: CryptoHandshakeMessage);
}

/// A class for framing the crypto messages that are exchanged in a QUIC session.
///
/// It has a `CryptoFramerVisitor` that is called when packets are parsed.
pub struct CryptoFramer<V> {
    visitor: V,
}

impl<V> CryptoFramer<V> {
    pub fn new(visitor: V) -> Self {
        CryptoFramer { visitor }
    }
}

impl<V> CryptoFramer<V>
where
    V: CryptoFramerVisitor,
{
    /// Processes input data, which must be delivered in order.
    pub fn process_input<P>(&self, input: &[u8]) -> Result<(), Error>
    where
        P: Perspective,
    {
        let (remaining, message) = CryptoHandshakeMessage::parse(input)?;

        debug_assert!(
            remaining.is_empty(),
            "unfinished handshake message, {:?}",
            remaining
        );

        self.visitor.on_handshake_message(message);

        Ok(())
    }
}
