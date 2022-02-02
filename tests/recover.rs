use fuel_crypto::{Error, Message, SecretKey, Signature};
use rand::rngs::StdRng;
use rand::SeedableRng;

#[test]
fn ecrecover() {
    let rng = &mut StdRng::seed_from_u64(8586);

    let message =
        b"A beast can never be as cruel as a human being, so artistically, so picturesquely cruel.";
    let message = Message::new(message);

    let secret = SecretKey::random(rng);
    let public = secret.public_key();

    let signature = secret.sign_recoverable(&message);
    let recover = signature.recover(&message).expect("Failed to recover PK");

    assert_eq!(public, recover);
}

#[test]
fn ecrecover_corrupted() {
    let rng = &mut StdRng::seed_from_u64(8586);

    let message = b"When life itself seems lunatic, who knows where madness lies?";
    let message = Message::new(message);

    let secret = SecretKey::random(rng);
    let public = secret.public_key();

    let signature = secret.sign_recoverable(&message);

    (0..Signature::LEN).for_each(|i| {
        (0..7).fold(1u8, |m, _| {
            let mut s = signature;

            s.as_mut()[i] ^= m;

            match s.recover(&message) {
                Ok(pk) => assert_ne!(public, pk),
                Err(Error::InvalidSignature) => (),
                Err(e) => panic!("Unexpected error: {}", e),
            }

            m << 1
        });
    });
}
