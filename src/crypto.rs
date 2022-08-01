use argon2;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::aead::NewAead;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

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
    const NONCE: &[u8; 12] = b"FixedNonce!!";

    pub fn new(secret: &str) -> Self {
        let pwd = secret.as_bytes();
        let salt = b"fixedsaltforargon";
        let config = argon2::Config {
            variant: argon2::Variant::Argon2id,
            hash_length: 32,
            ..Default::default()
        };
        let key = argon2::hash_raw(pwd, salt, &config).unwrap();
        CryptoState { key }
    }

    pub fn decrypt(&self, s: &str) -> Result<String, String> {
        let bytes = base64::decode_config(s, base64::URL_SAFE).map_err(|err| err.to_string())?;
        let nonce = Nonce::from_slice(CryptoState::NONCE);
        let ciphertext: &[u8] = &bytes;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|err| err.to_string())?;
        str::from_utf8(&plaintext)
            .map_err(|err| err.to_string())
            .map(str::to_owned)
    }

    pub fn encrypt(&self, plaintext: &str) -> String {
        let nonce = Nonce::from_slice(CryptoState::NONCE);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let ciphertext = cipher.encrypt(nonce, plaintext.as_bytes()).unwrap();
        base64::encode_config(ciphertext, base64::URL_SAFE)
    }
}

#[test]
fn test_reversability() {
    let c = CryptoState::new("secretkey");
    const PLAIN: &str = "some text which is not really long but not short either";
    let new_plain = c.decrypt(&c.encrypt(PLAIN)).expect("failed decryption");
    assert_eq!(PLAIN, new_plain);
}
