use crate::{Error, Keystore, Message, Signature};

/// Signature provider based on a keystore
pub trait Signer {
    /// Keystore error implementation
    type Error: From<Error> + From<<Self::Keystore as Keystore>::Error>;

    /// Concrete keystore implementation
    type Keystore: Keystore;

    /// Accessor to the keystore
    ///
    /// Might fail if the keystore is in a corrupt state, not initialized or locked by a
    /// concurrent thread.
    fn keystore(&self) -> Result<&Self::Keystore, Self::Error>;

    /// Sign a given message with the secret key identified by `id`
    #[cfg(not(feature = "std"))]
    fn sign(
        &self,
        id: &<Self::Keystore as Keystore>::KeyId,
        message: &Message,
    ) -> Result<Signature, Self::Error>;

    /// Sign a given message with the secret key identified by `id`
    #[cfg(feature = "std")]
    fn sign(
        &self,
        id: &<Self::Keystore as Keystore>::KeyId,
        message: &Message,
    ) -> Result<Signature, Self::Error> {
        let keystore = self.keystore()?;
        let secret = keystore.secret(id)?.ok_or_else(|| Error::KeyNotFound)?;

        Ok(Signature::sign(secret.as_ref(), message))
    }
}
