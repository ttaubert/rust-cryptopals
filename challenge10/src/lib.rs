extern crate openssl;
extern crate challenge2;
extern crate challenge4;
extern crate challenge6;
extern crate challenge7;

use openssl::crypto::symm as cipher;
use challenge2::Xor;
use challenge7::aes_128_ecb_decrypt;

pub fn aes_128_ecb_encrypt(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
  assert!(key.len() == 16 && plaintext.len() % 16 == 0);

  let cipher = cipher::Crypter::new(cipher::Type::AES_128_ECB);
  cipher.init(cipher::Mode::Encrypt, key, vec!());
  cipher.pad(false);

  let mut encrypted = cipher.update(plaintext);
  encrypted.extend(cipher.finalize().into_iter());
  encrypted
}

pub fn aes_128_cbc_encrypt(key: &[u8], plaintext: &[u8], iv: Vec<u8>) -> Vec<u8> {
  assert!(key.len() == 16 && plaintext.len() % 16 == 0 && iv.len() == 16);

  let mut iv = iv;
  let mut ciphertext = Vec::with_capacity(plaintext.len());

  for block in plaintext.chunks(16) {
    let encrypted = aes_128_ecb_encrypt(key, &iv.xor(block)[..]);
    ciphertext.extend(encrypted.clone());
    iv = encrypted;
  }

  ciphertext
}

pub fn aes_128_cbc_decrypt(key: &[u8], ciphertext: &[u8], iv: Vec<u8>) -> Vec<u8> {
  assert!(key.len() == 16 && ciphertext.len() % 16 == 0 && iv.len() == 16);

  let mut iv = &iv[..];
  let mut plaintext = Vec::with_capacity(ciphertext.len());

  for block in ciphertext.chunks(16) {
    let decrypted = aes_128_ecb_decrypt(key, block);
    plaintext.extend(decrypted.xor(iv));
    iv = block;
  }

  plaintext
}

#[cfg(test)]
mod test {
  use challenge4::read_file;
  use challenge6::Base64Decoder;
  use aes_128_cbc_encrypt;
  use aes_128_cbc_decrypt;

  #[test]
  fn test() {
    let data = read_file("data.txt").replace("\n", "").from_base64();

    let key = b"YELLOW SUBMARINE";
    let iv = vec!(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);
    let bytes = aes_128_cbc_decrypt(key, &data[..], iv.clone());

    let plaintext = String::from_utf8(bytes.clone()).unwrap();
    assert!(plaintext.starts_with("I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me"));
    assert_eq!(aes_128_cbc_encrypt(key, &bytes[..], iv), data);
  }
}
