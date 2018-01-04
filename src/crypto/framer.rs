use failure::Error;

use crypto::CryptoHandshakeMessage;
use types::Perspective;

pub trait MessageParser {
    fn process<P>(&self, input: &[u8]) -> Result<(), Error>
    where
        P: Perspective;
}

pub trait CryptoFramerVisitor {
    /// Called when a complete handshake message has been parsed.
    fn on_handshake_message(&self, message: CryptoHandshakeMessage);
}

pub struct CryptoFramer<V> {
    visitor: V,
}

impl<V> CryptoFramer<V> {
    pub fn new(visitor: V) -> Self {
        CryptoFramer { visitor }
    }
}

impl<V> MessageParser for CryptoFramer<V>
where
    V: CryptoFramerVisitor,
{
    fn process<P>(&self, input: &[u8]) -> Result<(), Error>
    where
        P: Perspective,
    {
        let (remaining, message) = CryptoHandshakeMessage::parse(input)?;

        self.visitor.on_handshake_message(message);

        Ok(())
    }
}
