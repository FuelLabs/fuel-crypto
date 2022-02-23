use crate::{Error, Keystore, Message, PublicKey, SecretKey, Signature};

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

    /// Secret key indexed by `id`.
    fn id_secret(
        &self,
        id: &<Self::Keystore as Keystore>::KeyId,
    ) -> Result<Borrown<'_, SecretKey>, Self::Error> {
        let keystore = self.keystore()?;
        let secret = keystore.secret(id)?.ok_or_else(|| Error::KeyNotFound)?;

        Ok(secret)
    }

    /// Public key indexed by `id`.
    fn id_public(
        &self,
        id: &<Self::Keystore as Keystore>::KeyId,
    ) -> Result<Borrown<'_, PublicKey>, Self::Error> {
        let keystore = self.keystore()?;
        let public = keystore.public(id)?.ok_or_else(|| Error::KeyNotFound)?;

        Ok(public)
    }

    /// Verify a given message with the public key identified by `id`
    fn verify(
        &self,
        id: &<Self::Keystore as Keystore>::KeyId,
        signature: Signature,
        message: &Message,
    ) -> Result<(), Self::Error> {
        let public = self.id_public(id)?;

        self.verify_with_key(public.as_ref(), signature, message)
    }

    /// Verify a given message with the provided key
    #[cfg(not(feature = "std"))]
    fn verify_with_key(
        &self,
        public: &PublicKey,
        signature: Signature,
        message: &Message,
    ) -> Result<(), Self::Error>;

    /// Verify a given message with the provided key
    #[cfg(feature = "std")]
    fn verify_with_key(
        &self,
        public: &PublicKey,
        signature: Signature,
        message: &Message,
    ) -> Result<(), Self::Error> {
        Ok(signature.verify(public, message)?)
    }
}
