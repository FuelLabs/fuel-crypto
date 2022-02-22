use fuel_crypto::borrown::Borrown;
use fuel_crypto::{Error, Keystore, Message, PublicKey, SecretKey, Signer};
use rand::rngs::StdRng;
use rand::SeedableRng;

use std::io;

#[derive(Debug, Default, Clone)]
struct TestKeystore {
    keys: Vec<SecretKey>,
}

impl TestKeystore {
    pub fn generate_key<R>(&mut self, rng: &mut R) -> usize
    where
        R: rand::Rng + ?Sized,
    {
        let n = self.keys.len();

        let secret = SecretKey::random(rng);

        self.keys.push(secret);

        n
    }
}

impl Keystore for TestKeystore {
    type Error = io::Error;
    type KeyId = usize;

    fn public(&self, id: &usize) -> Result<Option<Borrown<'_, PublicKey>>, io::Error> {
        self.secret(id)?
            .ok_or_else(|| Error::KeyNotFound.into())
            .map(|secret| PublicKey::from(secret.as_ref()))
            .map(Borrown::from)
            .map(Some)
    }

    fn secret(&self, id: &usize) -> Result<Option<Borrown<'_, SecretKey>>, io::Error> {
        Ok(self.keys.get(*id).map(Borrown::from))
    }
}

impl AsRef<TestKeystore> for TestKeystore {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl Signer for TestKeystore {
    type Keystore = Self;
}

#[test]
fn signer() {
    let rng = &mut StdRng::seed_from_u64(8586);

    let mut keystore = TestKeystore::default();

    let message = b"It is amazing how complete is the delusion that beauty is goodness.";
    let message = Message::new(message);

    let key = keystore.generate_key(rng);
    let key_p = keystore.generate_key(rng);

    assert_ne!(key, key_p);

    keystore
        .public(&key)
        .expect("Test keystore is infallible")
        .expect("PK was inserted");

    keystore
        .public(&key_p)
        .expect("Test keystore is infallible")
        .expect("PK was inserted");

    let signature = keystore.sign(&key, &message).expect("Failed to sign");
    let signature_p = keystore.sign(&key_p, &message).expect("Failed to sign");

    keystore
        .verify(&key, signature, &message)
        .expect("Failed to verify signature");

    keystore
        .verify(&key_p, signature_p, &message)
        .expect("Failed to verify signature");

    keystore
        .verify(&key_p, signature, &message)
        .err()
        .expect("Wrong key should fail verification");

    keystore
        .verify(&key, signature_p, &message)
        .err()
        .expect("Wrong key should fail verification");
}
