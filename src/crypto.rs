use anyhow::anyhow;
use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Key, KeyInit, Nonce};
use rand::Rng;
use rand_core::OsRng;
use serde::{de::DeserializeOwned, Serialize};
use tracing::warn;

use std::str;

#[derive(Clone, PartialEq, Eq)]
pub struct CryptoState {
    key: Vec<u8>,
}

impl CryptoState {
    /// Fixed nonce. We don't need the property that the same message is encrypted
    /// differently every single time. That would help prevent analysis if we would be
    /// communicating with lots of similar messages. We are mainly using the cipher for
    /// authentication and we want the message to be as short as possible.
    fn derive_key(secret: &str) -> Vec<u8> {
        let pwd = secret.as_bytes();
        let salt = b"fixedsaltforargon";
        let config = argon2::Config {
            variant: argon2::Variant::Argon2id,
            hash_length: 32,
            ..Default::default()
        };
        argon2::hash_raw(pwd, salt, &config).unwrap()
    }

    pub fn new(secret: &str) -> Self {
        CryptoState {
            key: CryptoState::derive_key(secret),
        }
    }

    pub fn is_secret_correct(&self, other_secret: &str) -> bool {
        self.key == CryptoState::derive_key(other_secret)
    }

    fn decrypt_raw(&self, s: &str) -> anyhow::Result<Vec<u8>> {
        let bytes = URL_SAFE.decode(s)?;
        let nonce = Nonce::from_slice(&bytes[bytes.len() - 12..]);
        let ciphertext: &[u8] = &bytes[..bytes.len() - 12];
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let res = cipher.decrypt(nonce, ciphertext).map_err(|e| {
            warn!("decryption error: {:?}", e);
            anyhow!(e)
        })?;
        Ok(res)
    }

    pub fn decrypt<T: DeserializeOwned>(&self, encrypted: String) -> anyhow::Result<T> {
        let v = self.decrypt_raw(&encrypted)?;
        ciborium::from_reader::<T, &[u8]>(&v).map_err(anyhow::Error::from)
    }

    fn encrypt_raw(&self, plaintext: &[u8]) -> String {
        let nonce = Nonce::from(OsRng.gen::<[u8; 12]>());
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let mut ciphertext = cipher.encrypt(&nonce, plaintext).unwrap();
        ciphertext.extend_from_slice(&nonce);
        URL_SAFE.encode(ciphertext)
    }

    pub fn encrypt<T: Serialize>(&self, o: T) -> String {
        let mut v = vec![];
        ciborium::into_writer(&o, &mut v).expect("serialization should never fail");
        self.encrypt_raw(&v)
    }
}

#[test]
fn test_reversability() {
    let c = CryptoState::new("secretkey");
    const PLAIN: &[u8] = b"some text which is not really long but not short either";
    let encrypted = c.encrypt_raw(PLAIN);
    let decrypted = c.decrypt_raw(&encrypted).expect("failed decryption");
    assert_eq!(PLAIN, &decrypted);
}

#[test]
fn test_encrypted_twice_with_different_results() {
    let c = CryptoState::new("secretkey");
    const PLAIN: &[u8] = b"plaintext";
    assert_ne!(c.encrypt_raw(PLAIN), c.encrypt_raw(PLAIN));
}
