extern crate challenge2;

use std::iter::FromIterator;

pub trait RepeatedXor {
  fn xor_repeat(&self, other: &[u8]) -> Vec<u8>;
}

impl RepeatedXor for [u8] {
  fn xor_repeat(&self, other: &[u8]) -> Vec<u8> {
    Vec::from_iter(self.iter().zip(other.iter().cycle()).map(|(a, b)| a ^ b))
  }
}

#[cfg(test)]
mod test {
  use challenge2::HexEncoder;
  use RepeatedXor;

  #[test]
  fn test() {
    let data = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";

    // Encrypt.
    let encrypted = data.xor_repeat(b"ICE");

    // Check.
    assert_eq!(encrypted.to_hex(), "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
  }
}
