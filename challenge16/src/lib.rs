extern crate rand;
extern crate challenge2;
extern crate challenge7;
extern crate challenge9;
extern crate challenge10;

use rand::{Rng, OsRng};
use challenge2::Xor;
use challenge7::aes_128_ecb_decrypt;
use challenge9::PKCS7Pad;
use challenge10::aes_128_cbc_encrypt;

static PREFIX: &'static[u8] = b"comment1=cooking%20MCs;userdata=";
static POSTFIX: &'static[u8] = b";comment2=%20like%20a%20pound%20of%20bacon";

pub fn aes_128_cbc_decrypt(key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
  assert!(key.len() == 16 && ciphertext.len() % 16 == 0);

  let mut iv = &ciphertext[..16];
  let mut plaintext = Vec::with_capacity(ciphertext.len() - 16);

  for block in ciphertext[16..].chunks(16) {
    let decrypted = aes_128_ecb_decrypt(key, block);
    plaintext.extend(decrypted.xor(iv));
    iv = block;
  }

  plaintext
}

pub struct BlackBox {
  key: [u8; 16]
}

impl BlackBox {
  pub fn new() -> BlackBox {
    let mut rng = OsRng::new().unwrap();

    // Generate a random key.
    let mut key = [0u8; 16];
    rng.fill_bytes(&mut key);

    BlackBox { key: key }
  }

  pub fn encrypt(&self, input: &str) -> Vec<u8> {
    let mut rng = OsRng::new().unwrap();

    // Remove meta chars.
    let input = input.replace(";", "");
    let input = input.replace("=", "");

    // Sandwich data between prefix and postfix.
    let mut data = PREFIX.to_vec();
    data.extend(input.as_bytes().to_vec());
    data.extend(POSTFIX.to_vec());

    // Pad to block size.
    let data = data.pkcs7_pad(16);

    // Generate a random IV.
    let mut iv = [0u8; 16];
    rng.fill_bytes(&mut iv);

    // Encrypt.
    let encryption = aes_128_cbc_encrypt(&self.key, &data, iv.to_vec());

    // Prepend IV to ciphertext.
    let mut data = iv.to_vec();
    data.extend(encryption);
    data
  }

  pub fn is_admin(&self, data: &[u8]) -> bool {
    let needle = b";admin=true;";
    let decryption = aes_128_cbc_decrypt(&self.key, &data);

    (0..decryption.len()-needle.len()).any(|i| {
      &decryption[i..i+needle.len()] == needle
    })
  }
}

#[cfg(test)]
mod test {
  use BlackBox;

  #[test]
  fn test() {
    let blackbox = BlackBox::new();

    // Block 1: comment1=cooking
    // Block 2: %20MCs;userdata= (will be garbled)
    // Block 3: aaaaa.admin.true
    // Rest:    ;comment2=%20like%20a%20pound%20of%20bacon
    let mut encrypted = blackbox.encrypt("aaaaa.admin.true");

    // Transform block 3 into "aaaaa;admin=true".
    encrypted[37] ^= b'.' ^ b';';
    encrypted[43] ^= b'.' ^ b'=';

    // Should have an admin profile.
    assert!(blackbox.is_admin(&encrypted));
  }

  #[test]
  fn test_encrypt() {
    let blackbox = BlackBox::new();
    let encrypted = blackbox.encrypt("asdf");
    assert!(!blackbox.is_admin(&encrypted));

    let encrypted = blackbox.encrypt(";admin=true;");
    assert!(!blackbox.is_admin(&encrypted));
  }
}
