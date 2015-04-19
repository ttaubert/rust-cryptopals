extern crate rand;
extern crate challenge6;
extern crate challenge11;
extern crate challenge12;

use rand::{Rng, OsRng};
use std::iter::{FromIterator, repeat};
use challenge11::is_ecb_blackbox;
use challenge12::determine_blocksize;

pub struct BlackBox {
  blackbox: challenge12::BlackBox,
  prefix: Vec<u8>,
}

impl BlackBox {
  pub fn new() -> BlackBox {
    let mut rng = OsRng::new().unwrap();

    // Generate a random prefix.
    let mut prefix = [0u8; 64];
    rng.fill_bytes(&mut prefix);
    let prefix = prefix[..rng.gen_range(1, 65)].to_vec();

    let blackbox = challenge12::BlackBox::new();
    BlackBox { blackbox: blackbox, prefix: prefix }
  }

  pub fn encrypt(&self, input: &[u8]) -> Vec<u8> {
    let mut data = self.prefix.clone();
    data.extend(input.to_vec());
    self.blackbox.encrypt(&data)
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

  // The padding we'll use to align the prefix to the block size.
  let pad = Vec::from_iter(repeat(0).take(prefix_pad));

  challenge12::decrypt_ecb(&|data| {
    // Concat pad and given data.
    let mut input = pad.clone();
    input.extend(data.to_vec());

    // Remove the prefix blocks.
    f(&input)[prefix..].to_vec()
  })
}

#[cfg(test)]
mod test {
  use challenge6::Base64Decoder;
  use challenge11::is_ecb_blackbox;
  use challenge12::{determine_blocksize, SECRET};
  use BlackBox;
  use decrypt_ecb;
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
}
