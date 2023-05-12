/// FuelMnemonic is a simple mnemonic phrase generator.
pub struct FuelMnemonic;

#[cfg(all(feature = "alloc", feature = "random"))]
mod use_alloc {
    extern crate alloc;
    use super::FuelMnemonic;
    use alloc::string::String;
    use coins_bip39::{English, Mnemonic};
    use rand::Rng;

    pub type W = English;

    impl FuelMnemonic {
        /// Generates a random mnemonic phrase given a random number generator and
        /// the number of words to generate, `count`.
        pub fn generate_mnemonic_phrase<R: Rng>(
            rng: &mut R,
            count: usize,
        ) -> Result<String, crate::Error> {
            Ok(Mnemonic::<W>::new_with_count(rng, count)?.to_phrase()?)
        }
    }
}
