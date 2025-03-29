// Copyright © Aptos Foundation
// SPDX-License-Identifier: Apache-2.0
//! This module provides APIs for private keys and public keys used in Secp256k1 ecdsa.
//! Version 2 of the secp256k1 ecdsa implementation using k256 crate instead of libsecp256k1.
//!
use crate::{
    hash::{CryptoHash, HashValue},
    traits,
    traits::{CryptoMaterialError, ValidCryptoMaterial, ValidCryptoMaterialStringExt},
};
use anyhow::{anyhow, Result};
use aptos_crypto_derive::{key_name, DeserializeKey, SerializeKey, SilentDebug, SilentDisplay};
use core::convert::TryFrom;
use k256::elliptic_curve::scalar::IsHigh;
use serde::Serialize;
use signature::hazmat::PrehashVerifier as _;

/// Expects pre-hashed messages of 32-bytes.
pub const MESSAGE_LENGTH: usize = 32;
/// Pre-hashed message type alias
pub type PrehashedMessage = [u8; MESSAGE_LENGTH];

/// Secp256k1 ecdsa private keys are 256-bit.
pub const PRIVATE_KEY_LENGTH: usize = 32;
/// Secp256k1 ecdsa public keys contain a prefix indicating compression and two 32-byte coordinates.
pub const PUBLIC_KEY_LENGTH: usize = 65;
/// Secp256k1 ecdsa signatures are 256-bit.
pub const SIGNATURE_LENGTH: usize = 64;

/// Secp256k1 ecdsa private key
#[derive(DeserializeKey, Eq, PartialEq, SerializeKey, SilentDebug, SilentDisplay)]
#[key_name("Secp256k1EcdsaPrivateKey")]
pub struct PrivateKey(pub(crate) k256::ecdsa::SigningKey);

#[cfg(feature = "assert-private-keys-not-cloneable")]
static_assertions::assert_not_impl_any!(PrivateKey: Clone);

#[cfg(any(test, feature = "cloneable-private-keys"))]
impl Clone for PrivateKey {
    fn clone(&self) -> Self {
        let serialized: &[u8] = &(self.to_bytes());
        PrivateKey::try_from(serialized).unwrap()
    }
}

impl PrivateKey {
    /// Serialize the private key into a byte vector
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    fn sign(&self, prehash: &PrehashedMessage) -> signature::Result<Signature> {
        let (signature, _recovery_id) = self.0.sign_prehash_recoverable(prehash)?;
        Ok(Signature(signature))
    }

    /// Private function aimed at minimizing code duplication between sign
    /// methods of the SigningKey implementation. This should remain private.
    #[cfg(any(test, feature = "fuzzing"))]
    fn sign_arbitrary_message(&self, message: &[u8]) -> signature::Result<Signature> {
        let message =
            bytes_to_prehash_message(message).expect("Consistently hashed to 32-bytes, should never fail.");
        // k256 ensures that the s in signature is normalized
        self.sign(&message)
    }
}

impl TryFrom<&[u8]> for PrivateKey {
    type Error = CryptoMaterialError;

    fn try_from(bytes: &[u8]) -> std::result::Result<PrivateKey, CryptoMaterialError> {
        match k256::ecdsa::SigningKey::from_slice(bytes) {
            Ok(private_key) => Ok(PrivateKey(private_key)),
            Err(_) => Err(CryptoMaterialError::DeserializationError),
        }
    }
}

impl traits::Length for PrivateKey {
    fn length(&self) -> usize {
        // The serialized private key is expected to be 32 bytes
        PRIVATE_KEY_LENGTH
    }
}

impl traits::PrivateKey for PrivateKey {
    type PublicKeyMaterial = PublicKey;
}

impl traits::SigningKey for PrivateKey {
    type SignatureMaterial = Signature;
    type VerifyingKeyMaterial = PublicKey;

    fn sign<T: CryptoHash + Serialize>(
        &self,
        message: &T,
    ) -> Result<Signature, CryptoMaterialError> {
        match bytes_to_prehash_message(&traits::signing_message_bcs(message)?) {
            Ok(message) => Ok(self
                .sign(&message)
                .map_err(|e| CryptoMaterialError::SignatureSigningError(e.to_string()))?),
            Err(_) => Err(CryptoMaterialError::SerializationError),
        }
    }

    #[cfg(any(test, feature = "fuzzing"))]
    fn sign_arbitrary_message(&self, message: &[u8]) -> Signature {
        PrivateKey::sign_arbitrary_message(self, message).expect("Failed to sign arbitrary message")
    }
}

impl traits::Uniform for PrivateKey {
    fn generate<R>(rng: &mut R) -> Self
    where
        R: ::rand::RngCore + ::rand::CryptoRng,
    {
        loop {
            let mut ret = [0u8; PRIVATE_KEY_LENGTH];
            rng.fill_bytes(&mut ret);
            if let Ok(key) = k256::ecdsa::SigningKey::from_slice(&ret) {
                return Self(key);
            }
        }
    }
}

impl ValidCryptoMaterial for PrivateKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes()
    }
}

/// Secp256k1 ecds public key
#[derive(DeserializeKey, Clone, Eq, PartialEq, SerializeKey)]
#[key_name("Secp256k1EcdsaPublicKey")]
pub struct PublicKey(pub(crate) k256::ecdsa::VerifyingKey);

impl PublicKey {
    /// Serialize the public key into a byte vector (full length)
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_sec1_bytes().to_vec()
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "secp256k1_ecdsa::PublicKey({})", self)
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.to_bytes()[..]))
    }
}

impl std::hash::Hash for PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let encoded_public_key = self.to_bytes();
        state.write(&encoded_public_key);
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = CryptoMaterialError;

    fn try_from(bytes: &[u8]) -> std::result::Result<PublicKey, CryptoMaterialError> {
        match k256::ecdsa::VerifyingKey::from_sec1_bytes(bytes) {
            Ok(public_key) => Ok(PublicKey(public_key)),
            Err(_) => Err(CryptoMaterialError::DeserializationError),
        }
    }
}

impl From<&PrivateKey> for PublicKey {
    fn from(private_key: &PrivateKey) -> Self {
        PublicKey(private_key.0.verifying_key().clone())
    }
}

impl traits::PublicKey for PublicKey {
    type PrivateKeyMaterial = PrivateKey;
}

impl traits::Length for PublicKey {
    fn length(&self) -> usize {
        PUBLIC_KEY_LENGTH
    }
}

impl ValidCryptoMaterial for PublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes()
    }
}

impl traits::VerifyingKey for PublicKey {
    type SignatureMaterial = Signature;
    type SigningKeyMaterial = PrivateKey;
}

/// Secp256k1 ecdsa signature
#[derive(DeserializeKey, Clone, SerializeKey)]
#[key_name("Secp256k1EcdsaSignature")]
pub struct Signature(pub(crate) k256::ecdsa::Signature);

impl Signature {
    /// Serialize the signature into a byte vector
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    fn verify(
        &self,
        message: &PrehashedMessage,
        public_key: &k256::ecdsa::VerifyingKey,
    ) -> Result<()> {
        // Prevent malleability attacks, low order only. The library only signs in low
        // order, so this was done intentionally.
        // See https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#low-s-values-in-signatures

        if self.0.s().is_high().into() {
            return Err(anyhow!(CryptoMaterialError::CanonicalRepresentationError));
        } 
        
        match public_key.verify_prehash(message, &self.0) {
            Ok(_) => Ok(()),
            Err(e) => Err(anyhow!("Unable to verify signature: {e:?}")),
        }
    }
}

impl Eq for Signature {}

impl PartialEq for Signature {
    fn eq(&self, other: &Signature) -> bool {
        self.to_bytes()[..] == other.to_bytes()[..]
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = CryptoMaterialError;

    fn try_from(bytes: &[u8]) -> std::result::Result<Signature, CryptoMaterialError> {
        match k256::ecdsa::Signature::from_slice(bytes) {
            Ok(signature) => Ok(Signature(signature)),
            Err(_) => Err(CryptoMaterialError::DeserializationError),
        }
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "secp256k1_ecdsa::Signature({})", self)
    }
}

impl std::fmt::Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.to_bytes()[..]))
    }
}

impl std::hash::Hash for Signature {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(&self.to_bytes());
    }
}

impl traits::Signature for Signature {
    type SigningKeyMaterial = PrivateKey;
    type VerifyingKeyMaterial = PublicKey;

    fn verify<T: CryptoHash + Serialize>(&self, message: &T, public_key: &PublicKey) -> Result<()> {
        let message = bytes_to_prehash_message(&traits::signing_message_bcs(message)?)?;
        self.verify(&message, &public_key.0)
    }

    fn verify_arbitrary_msg(&self, message: &[u8], public_key: &PublicKey) -> Result<()> {
        let message = bytes_to_prehash_message(message)?;
        self.verify(&message, &public_key.0)
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes()
    }
}

impl traits::Length for Signature {
    fn length(&self) -> usize {
        SIGNATURE_LENGTH
    }
}

impl ValidCryptoMaterial for Signature {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes()
    }
}

fn bytes_to_prehash_message(message: &[u8]) -> Result<[u8; MESSAGE_LENGTH]> {
    let message_digest = HashValue::sha3_256_of(message).to_vec();
    message_digest
        .try_into()
        .map_err(|_| anyhow!("Failed to convert message digest to [u8; MESSAGE_LENGTH]"))
}
