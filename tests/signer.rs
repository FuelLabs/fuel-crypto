use fuel_crypto::borrown::Borrown;
use fuel_crypto::{Keystore, Message, PublicKey, SecretKey, Signer};
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

    fn public(&self, id: &usize) -> Result<Borrown<'_, PublicKey>, io::Error> {
        self.secret(id)
            .map(|secret| PublicKey::from(secret.as_ref()))
            .map(Borrown::from)
    }

    fn public_identity_exists(&self, public: &PublicKey) -> Result<(), Self::Error> {
        self.keys
            .iter()
            .map(PublicKey::from)
            .any(|p| &p == public)
            .then(|| ())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "The provided public key wasn't found",
                )
            })
    }

    fn secret(&self, id: &usize) -> Result<Borrown<'_, SecretKey>, io::Error> {
        self.keys
            .get(*id)
            .map(Borrown::from)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "The key was not found"))
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

    let public = keystore.public(&key).expect("Failed to fetch PK");
    let public_p = keystore.public(&key).expect("Failed to fetch PK");

    keystore
        .public_identity_exists(public.as_ref())
        .expect("PK was inserted");

    keystore
        .public_identity_exists(public_p.as_ref())
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
