//! Adapt RFC 9180 contexts to rustls without linking a second TLS crypto provider.
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable,
    aead::{Aead, AeadCtxR, AeadCtxS, AesGcm128, AesGcm256, ChaCha20Poly1305},
    kdf::HkdfSha256,
    kem::X25519HkdfSha256 as Kem,
};
use rand_core_06::OsRng;
use rustls::{
    Error,
    crypto::hpke::{
        EncapsulatedSecret, Hpke, HpkeOpener, HpkePrivateKey, HpkePublicKey, HpkeSealer, HpkeSuite,
    },
    internal::msgs::{
        enums::{HpkeAead, HpkeKdf, HpkeKem},
        handshake::HpkeSymmetricCipherSuite,
    },
};
use std::{fmt, marker::PhantomData};

pub(crate) const SUITES: &[&dyn Hpke] = &[
    &Suite::<AesGcm128>(PhantomData),
    &Suite::<AesGcm256>(PhantomData),
    &Suite::<ChaCha20Poly1305>(PhantomData),
];

struct Suite<A>(PhantomData<A>);
struct Sender<A: Aead>(AeadCtxS<A, HkdfSha256, Kem>);
struct Receiver<A: Aead>(AeadCtxR<A, HkdfSha256, Kem>);

// Contexts contain keys and must never expose their state through Debug.
macro_rules! opaque_debug {
    ($name:ident) => {
        impl<A: Aead> fmt::Debug for $name<A> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(stringify!($name))
            }
        }
    };
}
opaque_debug!(Suite);
opaque_debug!(Sender);
opaque_debug!(Receiver);

fn error(e: hpke::HpkeError) -> Error {
    Error::General(e.to_string())
}

impl<A: Aead + Send + Sync + 'static> Hpke for Suite<A> {
    fn suite(&self) -> HpkeSuite {
        HpkeSuite {
            kem: HpkeKem::DHKEM_X25519_HKDF_SHA256,
            sym: HpkeSymmetricCipherSuite {
                kdf_id: HpkeKdf::HKDF_SHA256,
                aead_id: HpkeAead::from(A::AEAD_ID),
            },
        }
    }
    fn setup_sealer(
        &self,
        info: &[u8],
        key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Box<dyn HpkeSealer>), Error> {
        let public = <Kem as KemTrait>::PublicKey::from_bytes(&key.0).map_err(error)?;
        let (enc, sender) =
            hpke::setup_sender::<A, HkdfSha256, Kem, _>(&OpModeS::Base, &public, info, &mut OsRng)
                .map_err(error)?;
        Ok((
            EncapsulatedSecret(enc.to_bytes().to_vec()),
            Box::new(Sender(sender)),
        ))
    }
    fn seal(
        &self,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Vec<u8>), Error> {
        let (enc, mut sender) = self.setup_sealer(info, key)?;
        Ok((enc, sender.seal(aad, plaintext)?))
    }
    fn setup_opener(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        key: &HpkePrivateKey,
    ) -> Result<Box<dyn HpkeOpener>, Error> {
        let private =
            <Kem as KemTrait>::PrivateKey::from_bytes(key.secret_bytes()).map_err(error)?;
        let enc = <Kem as KemTrait>::EncappedKey::from_bytes(&enc.0).map_err(error)?;
        let receiver =
            hpke::setup_receiver::<A, HkdfSha256, Kem>(&OpModeR::Base, &private, &enc, info)
                .map_err(error)?;
        Ok(Box::new(Receiver(receiver)))
    }
    fn open(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        key: &HpkePrivateKey,
    ) -> Result<Vec<u8>, Error> {
        self.setup_opener(enc, info, key)?.open(aad, ciphertext)
    }
    fn generate_key_pair(&self) -> Result<(HpkePublicKey, HpkePrivateKey), Error> {
        let (private, public) = Kem::gen_keypair(&mut OsRng);
        Ok((
            HpkePublicKey(public.to_bytes().to_vec()),
            private.to_bytes().to_vec().into(),
        ))
    }
}

impl<A: Aead + Send + Sync + 'static> HpkeSealer for Sender<A> {
    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        self.0.seal(plaintext, aad).map_err(error)
    }
}
impl<A: Aead + Send + Sync + 'static> HpkeOpener for Receiver<A> {
    fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        self.0.open(ciphertext, aad).map_err(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interoperates_with_aws_lc_across_messages_and_checks_aad() {
        for &local in SUITES {
            let peer = rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES
                .iter()
                .copied()
                .find(|peer| peer.suite() == local.suite())
                .unwrap();
            let (public, private) = peer.generate_key_pair().unwrap();
            let (enc, mut sender) = local.setup_sealer(b"ech test", &public).unwrap();
            let mut receiver = peer.setup_opener(&enc, b"ech test", &private).unwrap();
            for message in [b"first".as_slice(), b"second"] {
                let encrypted = sender.seal(b"aad", message).unwrap();
                assert_eq!(receiver.open(b"aad", &encrypted).unwrap(), message);
            }
            let (public, private) = local.generate_key_pair().unwrap();
            let (enc, ct) = peer.seal(b"context", b"aad", b"secret", &public).unwrap();
            assert_eq!(
                local.open(&enc, b"context", b"aad", &ct, &private).unwrap(),
                b"secret"
            );
            assert!(
                local
                    .open(&enc, b"context", b"wrong", &ct, &private)
                    .is_err()
            );
        }
    }
}
