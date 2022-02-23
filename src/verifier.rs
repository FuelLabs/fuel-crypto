use crate::{Error, Keystore, Message, PublicKey, Signature};

use borrown::Borrown;

/// Signature verifier based on a keystore
pub trait Verifier {
    /// Keystore error implementation
    type Error: From<Error> + From<<Self::Keystore as Keystore>::Error>;

    /// Concrete keystore implementation
    type Keystore: Keystore;

    /// Accessor to the keystore
    ///
    /// Might fail if the keystore is in a corrupt state, not initialized or locked by a
    /// concurrent thread.
    fn keystore(&self) -> Result<&Self::Keystore, Self::Error>;

    /// Public key indexed by `id`.
    fn public(
        &self,
        id: &<Self::Keystore as Keystore>::KeyId,
    ) -> Result<Borrown<'_, PublicKey>, Self::Error> {
        let keystore = self.keystore()?;
        let public = keystore.public(id)?.ok_or_else(|| Error::KeyNotFound)?;

        Ok(public)
    }

    /// Verify a given message with the public key identified by `id`
    #[cfg(not(feature = "std"))]
    fn verify(
        &self,
        id: &<Self::Keystore as Keystore>::KeyId,
        signature: Signature,
        message: &Message,
    ) -> Result<(), Self::Error>;

    /// Verify a given message with the public key identified by `id`
    #[cfg(feature = "std")]
    fn verify(
        &self,
        id: &<Self::Keystore as Keystore>::KeyId,
        signature: Signature,
        message: &Message,
    ) -> Result<(), Self::Error> {
        let public = self.public(id)?;

        Ok(signature.verify(public.as_ref(), message)?)
    }
}
