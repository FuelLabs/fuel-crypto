/// FuelMnemonic is a simple mnemonic phrase generator.
pub struct FuelMnemonic;

#[cfg(feature = "std")]
mod use_std {
    use super::FuelMnemonic;
    use crate::{Error, SecretKey};
    use coins_bip32::path::DerivationPath;
    use coins_bip39::{English, Mnemonic};
    #[cfg(feature = "random")]
    use rand::Rng;
    use std::str::FromStr;

    type W = English;

    impl SecretKey {
        /// Generate a new secret key from a mnemonic phrase and its derivation path.
        /// The derivation path is a list of integers, each representing a child index.
        pub fn new_from_mnemonic_phrase_with_path(phrase: &str, path: &str) -> Result<Self, Error> {
            let mnemonic = Mnemonic::<W>::new_from_phrase(phrase)?;

            let path = DerivationPath::from_str(path)?;

            let derived_priv_key = mnemonic.derive_key(path, None)?;
            let key: &coins_bip32::prelude::SigningKey = derived_priv_key.as_ref();
            Ok(unsafe { SecretKey::from_slice_unchecked(key.to_bytes().as_ref()) })
        }
    }

    impl FuelMnemonic {
        /// Generates a random mnemonic phrase given a random number generator and
        /// the number of words to generate, `count`.
        #[cfg(feature = "random")]
        pub fn generate_mnemonic_phrase<R: Rng>(
            rng: &mut R,
            count: usize,
        ) -> Result<String, Error> {
            Ok(Mnemonic::<W>::new_with_count(rng, count)?.to_phrase()?)
        }
    }
}
