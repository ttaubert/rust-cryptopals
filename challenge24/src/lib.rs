extern crate rand;
extern crate challenge2;
extern crate challenge21;
extern crate challenge22;

use rand::{Rng, OsRng, SeedableRng};
use std::iter::FromIterator;
use challenge2::Xor;
use challenge21::MT19937RNG;
use challenge22::unix_time;

const TEXT: &'static [u8; 14] = b"AAAAAAAAAAAAAA";

pub fn mt19337_transform(seed: u32, data: &[u8]) -> Vec<u8> {
  let mut rng = MT19937RNG::from_seed(seed);
  let key = rng.gen_iter().take(data.len());
  Vec::from_iter(key).xor(&data)
}

pub struct BlackBox {
  seed: u32
}

impl BlackBox {
  pub fn new() -> Self {
    let mut rng = OsRng::new().unwrap();
    BlackBox { seed: rng.next_u32() & 0xffff }
  }

  pub fn ticket() -> [u8; 16] {
    let mut ticket = [0; 16];
    let mut rng = MT19937RNG::from_seed(unix_time());
    rng.fill_bytes(&mut ticket);
    ticket
  }

  pub fn encrypt(&self) -> Vec<u8> {
    let mut rng = OsRng::new().unwrap();
    let mut prefix = [0; 64];
    rng.fill_bytes(&mut prefix);

    // Prefix with 32-64 random bytes.
    let prefix = &prefix[..rng.gen_range(32, 64)];

    // Append the constant text.
    let mut data = prefix.to_vec();
    data.extend(TEXT.to_vec());

    // Encrypt with an MT stream cipher.
    mt19337_transform(self.seed, &data)
  }
}

pub fn find_mt19337_seed(ciphertext: &[u8]) -> u32 {
  // Try all 16 bit seeds.
  for seed in 0..65536 {
    let plaintext = mt19337_transform(seed, ciphertext);
    if &plaintext[plaintext.len()-TEXT.len()..] == TEXT {
      return seed;
    }
  }

  panic!("shouldn't reach this");
}

pub fn is_ticket(ticket: &[u8; 16]) -> bool {
  let now = unix_time();
  let mut candidate = [0; 16];

  // Check seeds around current unix time.
  (now-5..now+5).any(|seed| {
    let mut rng = MT19937RNG::from_seed(seed);
    rng.fill_bytes(&mut candidate);
    &candidate == ticket
  })
}

#[cfg(test)]
mod test {
  use TEXT;
  use BlackBox;
  use is_ticket;
  use mt19337_transform;
  use find_mt19337_seed;

  #[test]
  fn test() {
    let blackbox = BlackBox::new();
    let ciphertext = blackbox.encrypt();
    let seed = find_mt19337_seed(&ciphertext);
    let plaintext = mt19337_transform(seed, &ciphertext);
    assert_eq!(&plaintext[plaintext.len()-TEXT.len()..], TEXT);
  }

  #[test]
  fn test_ticket() {
    let ticket = BlackBox::ticket();
    assert!(is_ticket(&ticket));
  }

  #[test]
  fn test_transform() {
    let data = b"This is a test.";

    let ciphertext = mt19337_transform(12345, data);
    assert!(ciphertext != b"This is a test.");

    let plaintext = mt19337_transform(12345, &ciphertext);
    assert_eq!(plaintext, data);
  }
}
