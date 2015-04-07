extern crate challenge1;

use std::char;

pub struct XOR<'a> {
  bytes: &'a [u8],
  bytes2: &'a [u8],
  index: usize
}

impl<'a> XOR<'a> {
  pub fn new(bytes: &'a [u8], bytes2: &'a [u8]) -> XOR<'a> {
    assert!(bytes.len() == bytes2.len());
    XOR { bytes: bytes, bytes2: bytes2, index: 0 }
  }
}

impl<'a> Iterator for XOR<'a> {
  type Item = u8;

  #[inline]
  fn next(&mut self) -> Option<<Self as Iterator>::Item> {
    if self.index >= self.bytes.len() {
      return None;
    }

    let index = self.index;
    self.index += 1;

    Some(self.bytes[index] ^ self.bytes2[index])
  }
}

pub struct HexEncoder<'a> {
  bytes: &'a [u8],
  index: usize,
  nchar: usize
}

impl<'a> HexEncoder<'a> {
  pub fn new(bytes: &'a [u8]) -> HexEncoder<'a> {
    HexEncoder { bytes: bytes, index: 0, nchar: 0 }
  }

  fn character(&self, num: u8) -> Option<char> {
    assert!(num < 16);
    let num = num as u32;

    if num < 10 {
      char::from_u32('0' as u32 + num)
    } else {
      char::from_u32('a' as u32 + num - 10)
    }
  }
}

impl<'a> Iterator for HexEncoder<'a> {
  type Item = char;

  #[inline]
  fn next(&mut self) -> Option<<Self as Iterator>::Item> {
    // Bail out early if we're done.
    if self.index >= self.bytes.len() {
      return None;
    }

    let nchar = self.nchar;
    self.nchar = (self.nchar + 1) % 2;

    if nchar == 0 {
      return self.character(self.bytes[self.index] / 16);
    }

    let index = self.index;
    self.index += 1;

    return self.character(self.bytes[index] % 16);
  }
}

#[cfg(test)]
mod test {
  use std::iter::FromIterator;
  use challenge1::HexDecoder;
  use HexEncoder;
  use XOR;

  #[test]
  fn test() {
    let decoder = HexDecoder::new("1c0111001f010100061a024b53535009181c");
    let bytes = Vec::from_iter(decoder);

    let decoder = HexDecoder::new("686974207468652062756c6c277320657965");
    let bytes2 = Vec::from_iter(decoder);

    let xor = XOR::new(&bytes[..], &bytes2[..]);
    let xored = Vec::from_iter(xor);

    let encoder = HexEncoder::new(&xored[..]);
    assert!(String::from_iter(encoder) == "746865206b696420646f6e277420706c6179");
  }
}
