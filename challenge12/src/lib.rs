extern crate rand;
extern crate challenge6;
extern crate challenge9;
extern crate challenge10;
extern crate challenge11;

use rand::{Rng, OsRng};
use std::iter::{FromIterator, repeat};
use std::ops::Range;
use challenge6::Base64Decoder;
use challenge9::PKCS7Pad;
use challenge10::aes_128_ecb_encrypt;
use challenge11::is_ecb_blackbox;

static SECRET: &'static str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

pub struct BlackBox {
  key: [u8; 16],
  secret: Vec<u8>
}

impl BlackBox {
  pub fn new() -> BlackBox {
    let mut rng = OsRng::new().unwrap();

    // Generate a random key.
    let mut key = [0u8; 16];
    rng.fill_bytes(&mut key);

    BlackBox { key: key, secret: SECRET.from_base64() }
  }

  pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
    let mut data = data.to_vec();
    data.extend(self.secret.clone());

    // Pad to block size.
    let data = data.pkcs7_pad(16);

    // Encrypt.
    aes_128_ecb_encrypt(&self.key, &data)
  }
}

pub fn determine_blocksize<F>(f: F) -> usize where F: Fn(&[u8]) -> Vec<u8> {
  let mut input = vec!();
  let orig = f(&input).len();

  loop {
    // Append a byte to the input.
    input.push(0);

    let current = f(&input).len();
    if current > orig {
      return current - orig;
    }
  }
}

pub fn determine_padding<F>(f: F) -> usize where F: Fn(&[u8]) -> Vec<u8> {
  let mut input = vec!();
  let orig = f(&input).len();

  loop {
    // Append a byte to the input.
    input.push(0);

    if f(&input).len() > orig {
      return input.len();
    }
  }
}

pub fn decrypt_ecb<F>(f: &F) -> Vec<u8> where F: Fn(&[u8]) -> Vec<u8> {
  // First, get the block size.
  let blocksize = determine_blocksize(f);

  // This attack works for ECB only.
  assert!(is_ecb_blackbox(f, blocksize));

  // Determine padding length.
  let padding = determine_padding(f);

  // The length of the secret, including padding.
  let secret_len = f(b"").len();

  // Buffer to be passed to the black box and hold the decryption.
  let mut input = Vec::from_iter(repeat(0).take(secret_len));

  // The position of the encrypted guess.
  let guess = Range { start: secret_len - blocksize, end: secret_len };

  // Find the plaintext.
  for index in 0..secret_len-padding {
    // Append a padding block for every block we want to decrypt. It will shift
    // to the left with every new byte we guess and contain the plaintext of
    // the block prior to the one we want to decrypt.
    if index % blocksize == 0 {
      let block = input[guess.clone()].to_vec();
      input.extend(block);
    }

    // Shift to the left.
    input.remove(0);

    // Position of the current ciphertext block we are decrypting.
    let start = secret_len + index - index % 16;
    let target = Range { start: start, end: start + blocksize };

    // Try all 256 possible bytes.
    for byte in 0..256 {
      // Apply and encrypt our current guess.
      input[secret_len - 1] = byte as u8;
      let encryption = f(&input);

      // Stop when we found the correct byte.
      if encryption[guess.clone()] == encryption[target.clone()] {
        break;
      }
    }
  }

  // Carve the decryption out of the buffer.
  input[padding..secret_len].to_vec()
}

#[cfg(test)]
mod test {
  use challenge6::Base64Decoder;
  use challenge11::is_ecb_blackbox;
  use SECRET;
  use BlackBox;
  use decrypt_ecb;
  use determine_padding;
  use determine_blocksize;

  #[test]
  fn test() {
    let blackbox = BlackBox::new();
    let decrypted = decrypt_ecb(&|data| blackbox.encrypt(data));
    assert_eq!(decrypted, SECRET.from_base64());
  }

  #[test]
  fn test_ecb() {
    let blackbox = BlackBox::new();
    let blocksize = determine_blocksize(|data| blackbox.encrypt(data));
    assert!(is_ecb_blackbox(|data| blackbox.encrypt(data), blocksize));
  }

  #[test]
  fn test_blocksize() {
    let blackbox = BlackBox::new();
    assert_eq!(determine_blocksize(|data| blackbox.encrypt(data)), 16);
  }

  #[test]
  fn test_padding() {
    let blackbox = BlackBox::new();
    let padding = determine_padding(|data| blackbox.encrypt(data));
    let blocksize = determine_blocksize(|data| blackbox.encrypt(data));
    assert_eq!(padding, blocksize - SECRET.from_base64().len() % blocksize);
  }
}
