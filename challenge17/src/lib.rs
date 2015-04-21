extern crate rand;
extern crate challenge6;
extern crate challenge9;
extern crate challenge15;
extern crate challenge16;

use rand::{Rng, OsRng};
use challenge6::Base64Decoder;
use challenge9::PKCS7Pad;
use challenge15::PKCS7Unpad;
use challenge16::{aes_128_cbc_encrypt,aes_128_cbc_decrypt};

static SECRETS: [&'static str; 10] = [
  "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
  "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
  "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
  "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
  "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
  "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
  "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
  "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
  "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
  "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
];

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

    // Pick a random secret.
    let secret = SECRETS[rng.gen_range(0, SECRETS.len())];
    let secret = secret.from_base64();

    BlackBox { key: key, secret: secret }
  }

  pub fn encrypt(&self) -> Vec<u8> {
    let mut rng = OsRng::new().unwrap();

    // Pad to block size.
    let data = self.secret.pkcs7_pad(16);

    // Generate a random IV.
    let mut iv = [0u8; 16];
    rng.fill_bytes(&mut iv);

    // Encrypt.
    aes_128_cbc_encrypt(&self.key, &data, iv.to_vec())
  }

  pub fn is_valid_padding(&self, data: &[u8]) -> bool {
    let decrypted = aes_128_cbc_decrypt(&self.key, data);

    // Check padding.
    decrypted.pkcs7_unpad().is_some()
  }
}

pub fn recover_plaintext<F>(data: &[u8], is_valid_pad: F) -> Vec<u8>
    where F: Fn(&[u8]) -> bool
{
  assert!(data.len() >= 32);
  let num_blocks = data.len() / 16;
  let mut block = Vec::with_capacity(data.len());

  // For every pair of adjacent blocks...
  for b in (0..num_blocks-1).rev().map(|b| b * 16) {
    // Two blocks, the one to recover and the one prior to that.
    let mut tmp = data[b..b+32].to_vec();

    // For every byte in a 128-bit block...
    for pad in 1..17 {
      // Save the recovered byte.
      block.insert(0, recover_plaintext_byte(&tmp, pad, &is_valid_pad));

      // Apply the correct guess permanently to recover prior bytes.
      tmp[16 - pad] ^= block[0];
    }
  }

  // Remove padding from the end of the plaintext.
  block.pkcs7_unpad().expect("failed to recover plaintext")
}

pub fn recover_plaintext_byte<F>(data: &[u8], pad: usize, is_valid_pad: &F) -> u8
    where F: Fn(&[u8]) -> bool
{
  let mut data = data.to_vec();
  let pos = 16 - pad;

  // Scramble every byte prior to the one we're trying to recover to avoid
  // (accidentally) valid padding byte series messing with our guesses.
  let mut rng = OsRng::new().unwrap();
  rng.fill_bytes(&mut data[0..pos]);

  // Apply the current padding byte.
  for x in pos..16 {
    data[x] ^= pad as u8;
  }

  // Try all possible bytes.
  for byte in 0us..256 {
    let mut data = data.clone();

    // Apply current guess.
    data[pos] ^= byte as u8;

    if is_valid_pad(&data) {
      return byte as u8;
    }
  }

  panic!("failed to recover plaintext byte");
}

#[cfg(test)]
mod test {
  use BlackBox;
  use recover_plaintext;

  #[test]
  fn test() {
    let blackbox = BlackBox::new();
    let encrypted = blackbox.encrypt();

    // Decrypt CBC using a padding oracle.
    let decrypted = recover_plaintext(&encrypted, |data| {
      blackbox.is_valid_padding(data)
    });

    assert_eq!(blackbox.secret, decrypted);
  }
}
