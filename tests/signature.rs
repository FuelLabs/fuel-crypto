use fuel_crypto::{Hasher, PublicKey, SecretKey};
use rand::rngs::StdRng;
use rand::SeedableRng;

#[test]
fn ecrecover() {
    let rng = &mut StdRng::seed_from_u64(8586);

    let message =
        b"A beast can never be as cruel as a human being, so artistically, so picturesquely cruel.";

    let secret = SecretKey::random(rng);
    let public = secret.public_key();

    let signature = secret.sign(message);
    let recover = PublicKey::recover(signature, message).expect("Failed to recover PK");

    assert_eq!(public, recover);
}

#[test]
fn ecrecover_unchecked() {
    let rng = &mut StdRng::seed_from_u64(8586);

    let message =
        b"Music expresses that which cannot be put into words and that which cannot remain silent.";
    let message = Hasher::hash(message);

    let secret = SecretKey::random(rng);
    let public = secret.public_key();

    let signature = unsafe { secret.sign_unchecked(message) };
    let recover =
        unsafe { PublicKey::recover_unchecked(signature, message).expect("Failed to recover PK") };

    assert_eq!(public, recover);
}
