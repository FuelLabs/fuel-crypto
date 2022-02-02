use fuel_crypto::{Message, PublicKey, SecretKey, Signature};
use rand::rngs::StdRng;
use rand::SeedableRng;

#[test]
fn sign() {
    let rng = &mut StdRng::seed_from_u64(8586);

    let message = b"Writing is good, thinking is better. Cleverness is good, patience is better.";
    let message = Message::new(message);

    let secret = SecretKey::random(rng);
    let public = secret.public_key();

    let signature = secret.sign(&message);

    signature
        .verify(&public, &message)
        .expect("Failed to verify signature");

    let signature = secret.sign_recoverable(&message);
    let signature = Signature::from(signature);

    signature
        .verify(&public, &message)
        .expect("Failed to verify signature");
}

#[test]
fn sign_corrupted() {
    let rng = &mut StdRng::seed_from_u64(8586);

    let message =
        b"Music expresses that which cannot be put into words and that which cannot remain silent.";
    let message = Message::new(message);

    let secret = SecretKey::random(rng);
    let public = secret.public_key();

    let signature = secret.sign(&message);

    (0..Signature::LEN).for_each(|i| {
        (0..7).fold(1u8, |m, _| {
            let mut s = signature;

            s.as_mut()[i] ^= m;

            assert!(s.verify(&public, &message).is_err());

            m << 1
        });
    });

    (0..PublicKey::LEN).for_each(|i| {
        (0..7).fold(1u8, |m, _| {
            let mut p = public;

            p.as_mut()[i] ^= m;

            assert!(signature.verify(&p, &message).is_err());

            m << 1
        });
    });
}
