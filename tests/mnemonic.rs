use fuel_crypto::{FuelMnemonic, SecretKey};

#[test]
fn secret_key_from_mnemonic_phrase() {
    let phrase = "oblige salon price punch saddle immune slogan rare snap desert retire surprise";

    let expected_public_key = "30cc18506ed9d500fa348d1202bac14e9683b6d4cd7a02eb5357504d74ff2a19a8b672eb22c6509588424bab5c627515a9105b7ad25b7f948fcb5cd09448df5e";

    let secret = SecretKey::new_from_mnemonic_phrase_with_path(phrase, "m/44'/60'/0'/0/0")
        .expect("failed to create secret key from mnemonic phrase");

    let public = secret.public_key();

    assert_eq!(public.to_string(), expected_public_key);
}

#[test]
fn random_mnemonic_phrase() {
    // create rng
    let mut rng = rand::thread_rng();

    let phrase = FuelMnemonic::generate_mnemonic_phrase(&mut rng, 12)
        .expect("failed to generate mnemonic phrase");

    let _secret = SecretKey::new_from_mnemonic_phrase_with_path(&phrase, "m/44'/60'/0'/0/0")
        .expect("failed to create secret key from mnemonic phrase");
}
