use fuel_types::Bytes64;

use core::fmt;
use core::ops::Deref;

macro_rules! signature {
    ($i:ident) => {
        #[derive(Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(transparent)]
        /// Secp256k1 signature implementation
        pub struct $i(Bytes64);

        impl $i {
            /// Memory length of the type
            pub const LEN: usize = Bytes64::LEN;

            /// Add a conversion from arbitrary slices into owned
            ///
            /// # Safety
            ///
            /// There is no guarantee the provided bytes will fit the field. The field
            /// security can be checked with [`SecretKey::is_in_field`].
            pub unsafe fn from_bytes_unchecked(bytes: [u8; Self::LEN]) -> Self {
                Self(bytes.into())
            }

            /// Add a conversion from arbitrary slices into owned
            ///
            /// # Safety
            ///
            /// This function will not panic if the length of the slice is smaller than
            /// `Self::LEN`. Instead, it will cause undefined behavior and read random
            /// disowned bytes.
            ///
            /// There is no guarantee the provided bytes will fit the field.
            pub unsafe fn from_slice_unchecked(bytes: &[u8]) -> Self {
                Self(Bytes64::from_slice_unchecked(bytes))
            }

            /// Copy-free reference cast
            ///
            /// There is no guarantee the provided bytes will fit the field.
            ///
            /// # Safety
            ///
            /// Inputs smaller than `Self::LEN` will cause undefined behavior.
            pub unsafe fn as_ref_unchecked(bytes: &[u8]) -> &Self {
                // The interpreter will frequently make references to keys and values using
                // logically checked slices.
                //
                // This function will avoid unnecessary copy to owned slices for the interpreter
                // access
                &*(bytes.as_ptr() as *const Self)
            }
        }

        impl Deref for $i {
            type Target = [u8; $i::LEN];

            fn deref(&self) -> &[u8; $i::LEN] {
                self.0.deref()
            }
        }

        impl AsRef<[u8]> for $i {
            fn as_ref(&self) -> &[u8] {
                self.0.as_ref()
            }
        }

        impl AsMut<[u8]> for $i {
            fn as_mut(&mut self) -> &mut [u8] {
                self.0.as_mut()
            }
        }

        impl From<$i> for [u8; $i::LEN] {
            fn from(salt: $i) -> [u8; $i::LEN] {
                salt.0.into()
            }
        }

        impl fmt::LowerHex for $i {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        impl fmt::UpperHex for $i {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        impl fmt::Debug for $i {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        impl fmt::Display for $i {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                self.0.fmt(f)
            }
        }
    };
}

signature!(RecoverableSignature);
signature!(Signature);

#[cfg(feature = "std")]
mod use_std {
    use crate::{Error, Message, PublicKey, RecoverableSignature, Signature};

    use secp256k1::recovery::{RecoverableSignature as SecpRecoverableSignature, RecoveryId};
    use secp256k1::{Secp256k1, Signature as Secp256k1Signature};

    impl RecoverableSignature {
        // Internal API - this isn't meant to be made public because some assumptions and pre-checks
        // are performed prior to this call
        fn to_secp(&mut self) -> SecpRecoverableSignature {
            let v = ((self.as_mut()[32] & 0x90) >> 7) as i32;
            self.as_mut()[32] &= 0x7f;

            let v = RecoveryId::from_i32(v)
                .unwrap_or_else(|_| RecoveryId::from_i32(0).expect("0 is infallible recovery ID"));

            let signature = SecpRecoverableSignature::from_compact(self.as_ref(), v)
                .unwrap_or_else(|_| {
                    SecpRecoverableSignature::from_compact(&[0u8; 64], v)
                        .expect("Zeroed signature is infallible")
                });

            signature
        }

        pub(crate) fn from_secp(signature: SecpRecoverableSignature) -> Self {
            let (v, mut signature) = signature.serialize_compact();

            let v = v.to_i32();
            signature[32] |= (v << 7) as u8;

            // Safety: the security of this call reflects the security of secp256k1 FFI
            unsafe { RecoverableSignature::from_bytes_unchecked(signature) }
        }
    }

    impl From<RecoverableSignature> for Signature {
        fn from(mut signature: RecoverableSignature) -> Signature {
            use secp256k1::ffi::{self, CPtr, Signature as Secp256k1FFISignature};

            let signature = signature.to_secp();

            // Safety: FFI init
            let mut ret = unsafe { Secp256k1FFISignature::new() };

            // Safety: FFI call
            unsafe {
                ffi::recovery::secp256k1_ecdsa_recoverable_signature_convert(
                    ffi::secp256k1_context_no_precomp,
                    &mut ret,
                    signature.as_c_ptr(),
                )
            };

            let signature = Secp256k1Signature::from(ret);
            let signature = signature.serialize_compact();

            // Safety: transparent secp signature
            unsafe { Signature::from_bytes_unchecked(signature) }
        }
    }

    impl RecoverableSignature {
        /// Recover the public key from a signature performed with
        /// [`SecretKey::sign_recoverable`]
        pub fn recover(mut self, message: &Message) -> Result<PublicKey, Error> {
            let signature = self.to_secp();
            let message = message.to_secp();

            let pk = Secp256k1::new()
                .recover(&message, &signature)
                .map(|pk| PublicKey::from_secp(&pk))?;

            Ok(pk)
        }
    }

    impl Signature {
        /// Verify a signature produced by [`SecretKey::sign`]
        pub fn verify(self, pk: &PublicKey, message: &Message) -> Result<(), Error> {
            let signature = Secp256k1Signature::from_compact(self.as_ref())?;

            let message = message.to_secp();
            let pk = pk.to_secp()?;

            Secp256k1::verification_only().verify(&message, &signature, &pk)?;

            Ok(())
        }
    }
}
