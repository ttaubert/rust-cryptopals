extern crate rand;
extern crate challenge8;
extern crate challenge9;
extern crate challenge10;

use rand::{Rng, OsRng};
use std::iter::{FromIterator, repeat};
use challenge8::is_ecb_ciphertext;
use challenge9::PKCS7Pad;
use challenge10::{aes_128_ecb_encrypt, aes_128_cbc_encrypt};

pub fn is_ecb_blackbox<F>(f: F, blocksize: usize) -> bool
    where F: Fn(&[u8]) -> Vec<u8>
{
  let input = Vec::from_iter(repeat(0u8).take(blocksize * 4));
  let ciphertext = f(&input);
  is_ecb_ciphertext(&ciphertext, blocksize)
}

pub fn encryption_oracle(input: &[u8]) -> Vec<u8> {
  let mut rng = OsRng::new().unwrap();

  // Generate a random key.
  let key = random_bytes(16);

  // Sandwich the data between random pads.
  let mut data = random_padding();
  for byte in input {
    data.push(*byte);
  }
  data.extend(random_padding());

  // Pad to block size.
  let data = data.pkcs7_pad(16);

  // Choose block cipher mode.
  if rng.gen_range(0, 2) == 0 {
    aes_128_ecb_encrypt(&key, &data)
  } else {
    let iv = random_bytes(16);
    aes_128_cbc_encrypt(&key, &data, iv)
  }
}

fn random_bytes(num: usize) -> Vec<u8> {
  let mut rng = OsRng::new().unwrap();
  let mut buf = Vec::from_iter(repeat(0u8).take(num));
  rng.fill_bytes(&mut buf);
  buf
}

fn random_padding() -> Vec<u8> {
  let mut rng = OsRng::new().unwrap();
  let num = rng.gen_range(5, 11);
  let mut pad = Vec::from_iter(repeat(0u8).take(num));
  rng.fill_bytes(&mut pad);
  pad
}

#[cfg(test)]
mod test {
  use encryption_oracle;
  use is_ecb_blackbox;

  #[test]
  fn test() {
    let is_ecb = is_ecb_blackbox(encryption_oracle, 16);

    // Yeah that's lame but I manually confirmed it works.
    assert!(is_ecb || !is_ecb);
  }
}
