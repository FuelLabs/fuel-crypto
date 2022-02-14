use crate::{PublicKey, SecretKey};

/// Keys container
pub trait Keystore {
    /// Identifier for the keypair
    type KeyId;

    /// Public key for a given id
    fn public(&self, id: Self::KeyId) -> &PublicKey;

    /// Secret key for a given id
    fn secret(&self, id: Self::KeyId) -> &SecretKey;
}
