extern crate rand;
extern crate challenge6;
extern crate challenge9;
extern crate challenge10;
extern crate challenge11;
extern crate challenge12;

use rand::{Rng, OsRng};
use std::iter::{FromIterator, repeat};
use std::ops::Range;
use challenge6::Base64Decoder;
use challenge9::PKCS7Pad;
use challenge10::aes_128_ecb_encrypt;
use challenge11::is_ecb_blackbox;
use challenge12::determine_blocksize;

static SECRET: &'static str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

pub struct BlackBox {
  key: [u8; 16],
  prefix: Vec<u8>,
  secret: Vec<u8>
}

impl BlackBox {
  pub fn new() -> BlackBox {
    let mut rng = OsRng::new().unwrap();

    // Generate a random key.
    let mut key = [0u8; 16];
    rng.fill_bytes(&mut key);

    // Generate a random prefix.
    let mut prefix = [0u8; 64];
    rng.fill_bytes(&mut prefix);
    let prefix = prefix[..rng.gen_range(1, 65)].to_vec();

    BlackBox { key: key, prefix: prefix, secret: SECRET.from_base64() }
  }

  pub fn encrypt(&self, input: &[u8]) -> Vec<u8> {
    // Sandwich data between prefix and secret.
    let mut data = self.prefix.clone();
    data.extend(input.to_vec());
    data.extend(self.secret.clone());

    // Pad to block size.
    let data = data.pkcs7_pad(16);

    // Encrypt.
    aes_128_ecb_encrypt(&self.key, &data)
  }
}

pub fn determine_prefix_len<F>(f: F, blocksize: usize) -> usize
    where F: Fn(&[u8]) -> Vec<u8>
{
  let mut rng = OsRng::new().unwrap();
  let mut data = [0u8; 64];
  rng.fill_bytes(&mut data);

  // Two identical, random blocks.
  let block = &data[..blocksize];
  let mut data = block.to_vec();
  data.extend(block.to_vec());

  loop {
    let encryption = f(&data);
    let blocks = Vec::from_iter(encryption.chunks(blocksize));

    // Find two adjacent, identical ciphertext blocks.
    for (i, pair) in blocks.windows(2).enumerate() {
      if pair[0] == pair[1] {
        return i * blocksize - (data.len() - blocksize * 2);
      }
    }

    data.insert(0, 0);
  }
}

pub fn determine_padding<F>(f: F, blocksize: usize, prefix_len: usize) -> usize
    where F: Fn(&[u8]) -> Vec<u8>
{
  let prefix_pad = blocksize - prefix_len % blocksize;
  let mut input = Vec::from_iter(repeat(0).take(prefix_pad));
  let orig = f(&input).len();

  loop {
    // Append a byte to the input.
    input.push(0);

    if f(&input).len() > orig {
      return input.len() - prefix_pad;
    }
  }
}

pub fn decrypt_ecb<F>(f: &F) -> Vec<u8> where F: Fn(&[u8]) -> Vec<u8> {
  // First, get the block size.
  let blocksize = determine_blocksize(f);

  // This attack works for ECB only.
  assert!(is_ecb_blackbox(f, blocksize));

  // Determine the length of the random prefix.
  let prefix_len = determine_prefix_len(f, blocksize);
  // The padding needed to align the prefix with the block size.
  let prefix_pad = blocksize - prefix_len % blocksize;
  // The number of blocks the aligned padding fills.
  let prefix_blocks = (prefix_len as f32 / blocksize as f32).ceil();
  // The sizes in bytes of the aligned padding.
  let prefix = prefix_blocks as usize * blocksize;

  // Determine padding length.
  let padding = determine_padding(f, blocksize, prefix_len);

  // The length of the secret, including padding. The pad is computed
  // assuming that the prefix is padded to align with the block size.
  let mut input = Vec::from_iter(repeat(0).take(prefix_pad));
  let secret_len = f(&input).len() - prefix;

  // Buffer to be passed to the black box and hold the decryption.
  input.extend(Vec::from_iter(repeat(0).take(secret_len)));

  // The position of the encrypted guess.
  let end = prefix + secret_len;
  let guess = Range { start: end - blocksize, end: end };

  // Find the plaintext.
  for index in 0..secret_len-padding {
    // Append a padding block for every block we want to decrypt. It will shift
    // to the left with every new byte we guess and contain the plaintext of
    // the block prior to the one we want to decrypt.
    if index % blocksize == 0 {
      let end = prefix_pad + secret_len;
      let block = input[end-blocksize..end].to_vec();
      input.extend(block);
    }

    // Shift to the left.
    input.remove(0);

    // Position of the current ciphertext block we are decrypting.
    let start = prefix + secret_len + index - index % blocksize;
    let target = Range { start: start, end: start + blocksize };

    // Try all 256 possible bytes.
    for byte in 0..256 {
      // Apply and encrypt our current guess.
      input[prefix_pad + secret_len - 1] = byte as u8;
      let encryption = f(&input);

      // Stop when we found the correct byte.
      if encryption[guess.clone()] == encryption[target.clone()] {
        break;
      }
    }
  }

  // Carve the decryption out of the buffer.
  input[prefix_pad+padding..prefix_pad+secret_len].to_vec()
}

#[cfg(test)]
mod test {
  use challenge6::Base64Decoder;
  use challenge11::is_ecb_blackbox;
  use challenge12::determine_blocksize;
  use SECRET;
  use BlackBox;
  use decrypt_ecb;
  use determine_padding;
  use determine_prefix_len;

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
  fn test_prefix() {
    let blackbox = BlackBox::new();
    let blocksize = determine_blocksize(|data| blackbox.encrypt(data));
    let prefix_len = determine_prefix_len(|data| blackbox.encrypt(data), blocksize);
    assert_eq!(prefix_len, blackbox.prefix.len());
  }

  #[test]
  fn test_padding() {
    let blackbox = BlackBox::new();
    let blocksize = determine_blocksize(|data| blackbox.encrypt(data));
    let prefix_len = determine_prefix_len(|data| blackbox.encrypt(data), blocksize);
    let padding = determine_padding(|data| blackbox.encrypt(data), blocksize, prefix_len);
    assert_eq!(padding, blocksize - SECRET.from_base64().len() % blocksize);
  }
}
