use crate::{Error, Keystore, Message, SecretKey, Signature, PublicKey};

use borrown::Borrown;

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

    /// Secret key indexed by `id`.
    fn secret(
        &self,
        id: &<Self::Keystore as Keystore>::KeyId,
    ) -> Result<Borrown<'_, SecretKey>, Self::Error> {
        let keystore = self.keystore()?;
        let secret = keystore.secret(id)?.ok_or_else(|| Error::KeyNotFound)?;

        Ok(secret)
    }

    /// Public key indexed by `id`.
    fn public(
        &self,
        id: &<Self::Keystore as Keystore>::KeyId,
    ) -> Result<Borrown<'_, PublicKey>, Self::Error> {
        let keystore = self.keystore()?;
        let public = keystore.public(id)?.ok_or_else(|| Error::KeyNotFound)?;

        Ok(public)
    }

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
        let secret = self.secret(id)?;

        Ok(Signature::sign(secret.as_ref(), message))
    }
}
