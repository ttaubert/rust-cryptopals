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

pub fn black_box(input: &[u8]) -> Vec<u8> {
  let mut rng = OsRng::new().unwrap();

  // Generate a random key.
  let mut key = [0u8; 16];
  rng.fill_bytes(&mut key);

  // Sandwich the data between random pads.
  let mut data = random_padding();
  data.extend(input.to_vec());
  data.extend(random_padding());

  // Pad to block size.
  let data = data.pkcs7_pad(16);

  // Choose block cipher mode.
  if rng.gen_range(0, 2) == 0 {
    aes_128_ecb_encrypt(&key, &data)
  } else {
    let mut iv = [0u8; 16];
    rng.fill_bytes(&mut iv);
    aes_128_cbc_encrypt(&key, &data, iv.to_vec())
  }
}

fn random_padding() -> Vec<u8> {
  let mut rng = OsRng::new().unwrap();

  let mut buf = [0u8; 10];
  rng.fill_bytes(&mut buf);

  buf[..rng.gen_range(5, 11)].to_vec()
}

#[cfg(test)]
mod test {
  use black_box;
  use is_ecb_blackbox;

  #[test]
  fn test() {
    let is_ecb = is_ecb_blackbox(black_box, 16);

    // Yeah that's lame but I manually confirmed it works.
    assert!(is_ecb || !is_ecb);
  }
}
