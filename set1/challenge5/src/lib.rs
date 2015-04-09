extern crate challenge2;

pub struct RepeatingXor<'a> {
  key: &'a [u8],
  kindex: usize,
  bytes: &'a [u8],
  index: usize
}

impl<'a> RepeatingXor<'a> {
  pub fn new(key: &'a [u8], bytes: &'a [u8]) -> RepeatingXor<'a> {
    RepeatingXor { key: key, kindex: 0, bytes: bytes, index: 0 }
  }
}

impl<'a> Iterator for RepeatingXor<'a> {
  type Item = u8;

  #[inline]
  fn next(&mut self) -> Option<<Self as Iterator>::Item> {
    if self.index >= self.bytes.len() {
      return None;
    }

    let index = self.index;
    self.index += 1;

    let kindex = self.kindex;
    self.kindex = (self.kindex + 1) % self.key.len();

    Some(self.key[kindex] ^ self.bytes[index])
  }
}

#[cfg(test)]
mod test {
  use std::iter::FromIterator;
  use challenge2::HexEncoder;
  use RepeatingXor;

  #[test]
  fn test() {
    let key = ['I' as u8, 'C' as u8, 'E' as u8];
    let data = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";

    // Encrypt.
    let xor = RepeatingXor::new(&key, data.as_bytes());
    let xor = Vec::from_iter(xor);

    // Check.
    let encoder = HexEncoder::new(&xor[..]);
    assert_eq!(String::from_iter(encoder), "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
  }
}
