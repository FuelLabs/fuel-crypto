/// Crypto error variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Error {
    /// An ECDSA error
    #[cfg(feature = "std")]
    Secp256k1(secp256k1::Error),
}

#[cfg(feature = "std")]
mod use_std {
    use super::*;
    use secp256k1::Error as Secp256k1Error;
    use std::{error, fmt};

    impl From<Secp256k1Error> for Error {
        fn from(secp: Secp256k1Error) -> Self {
            Self::Secp256k1(secp)
        }
    }

    impl fmt::Display for Error {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Secp256k1(e) => e.fmt(f),
            }
        }
    }

    impl error::Error for Error {
        fn source(&self) -> Option<&(dyn error::Error + 'static)> {
            match self {
                Self::Secp256k1(e) => Some(e),
            }
        }
    }
}
