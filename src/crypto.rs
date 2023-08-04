use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Key, KeyInit, Nonce};
use rand::Rng;
use rand_core::OsRng;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

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

    fn decrypt_raw(&self, s: &str) -> Result<String, String> {
        let bytes = URL_SAFE.decode(s).map_err(|err| err.to_string())?;
        let nonce = Nonce::from_slice(&bytes[bytes.len() - 12..]);
        let ciphertext: &[u8] = &bytes[..bytes.len() - 12];
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|err| err.to_string())?;
        str::from_utf8(&plaintext)
            .map_err(|err| err.to_string())
            .map(str::to_owned)
    }

    pub fn decrypt<T: DeserializeOwned>(&self, encrypted: String) -> Result<T, String> {
        let raw = self.decrypt_raw(&encrypted)?;
        let res = serde_urlencoded::from_str(&raw).map_err(|e| e.to_string());
        res
    }

    fn encrypt_raw(&self, plaintext: &str) -> String {
        let nonce = Nonce::from(OsRng.gen::<[u8; 12]>());
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let mut ciphertext = cipher.encrypt(&nonce, plaintext.as_bytes()).unwrap();
        ciphertext.extend_from_slice(&nonce);
        URL_SAFE.encode(ciphertext)
    }

    pub fn encrypt<T: Serialize>(&self, o: T) -> String {
        self.encrypt_raw(&serde_urlencoded::to_string(o).unwrap())
    }
}

#[test]
fn test_reversability() {
    let c = CryptoState::new("secretkey");
    const PLAIN: &str = "some text which is not really long but not short either";
    let new_plain = c
        .decrypt_raw(&c.encrypt_raw(PLAIN))
        .expect("failed decryption");
    assert_eq!(PLAIN, new_plain);
}

#[test]
fn test_encrypted_twice_with_different_results() {
    let c = CryptoState::new("secretkey");
    const PLAIN: &str = "plaintext";
    assert_ne!(c.encrypt_raw(PLAIN), c.encrypt_raw(PLAIN));
}
