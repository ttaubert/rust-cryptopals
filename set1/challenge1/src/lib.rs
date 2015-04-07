use std::char;
use std::slice::Chunks;

pub struct HexDecoder<'a> {
  chunks: Chunks<'a, u8>
}

impl<'a> HexDecoder<'a> {
  pub fn new(v: &str) -> HexDecoder {
    assert!(v.len() % 2 == 0);
    HexDecoder { chunks: v.as_bytes().chunks(2) }
  }

  fn digit(&self, byte: u8) -> u8 {
    if byte >= 'a' as u8 {
      assert!(byte <= 'f' as u8);
      10 + byte - 'a' as u8
    } else if byte >= 'A' as u8 {
      assert!(byte <= 'F' as u8);
      10 + byte - 'A' as u8
    } else {
      assert!(byte <= '9' as u8);
      byte - '0' as u8
    }
  }
}

impl<'a> Iterator for HexDecoder<'a> {
  type Item = u8;

  #[inline]
  fn next(&mut self) -> Option<<Self as Iterator>::Item> {
    match self.chunks.next() {
      None => None,

      Some(chunk) => {
        Some(16 * self.digit(chunk[0]) + self.digit(chunk[1]))
      }
    }
  }
}

pub struct Base64Encoder<'a> {
  bytes: &'a [u8],
  index: usize,
  nchar: usize
}

impl<'a> Base64Encoder<'a> {
  pub fn new(bytes: &[u8]) -> Base64Encoder {
    Base64Encoder { bytes: bytes, index: 0, nchar: 0 }
  }

  fn to_base64_char(&self, idx: u8) -> Option<char> {
    // Zero the two MSBs.
    let idx = (idx & 0x3f) as u32;

    if idx < 26 {
      char::from_u32('A' as u32 + idx)
    } else if idx < 52 {
      char::from_u32('a' as u32 + (idx - 26))
    } else if idx < 62 {
      char::from_u32('0' as u32 + (idx - 52))
    } else {
      Some(if idx == 62 { '+' } else { '/' })
    }
  }
}

impl<'a> Iterator for Base64Encoder<'a> {
  type Item = char;

  #[inline]
  fn next(&mut self) -> Option<<Self as Iterator>::Item> {
    // Bail out early if we're done.
    if self.nchar == 0 && self.index >= self.bytes.len() {
      return None;
    }

    let nchar = self.nchar;
    self.nchar = (self.nchar + 1) % 4;

    // Don't need to increase the index as the fourth character is
    // built out of the remaining bits of the third byte only.
    if nchar == 3 && self.index <= self.bytes.len() {
      // 4th char = 6 LSBs of the third byte.
      return self.to_base64_char(self.bytes[self.index - 1]);
    }

    let index = self.index;
    self.index += 1;

    // Handle missing second and third bytes.
    if nchar == 1 && index == self.bytes.len() {
      // Assume the second byte is zero.
      return self.to_base64_char(self.bytes[index - 1] << 4);
    }

    // Handle a missing third byte.
    if nchar == 2 && index == self.bytes.len() {
      // Assume the third byte is zero.
      return self.to_base64_char(self.bytes[index - 1] << 2);
    }

    if index >= self.bytes.len() {
      // Padding.
      return Some('=');
    }

    let byte = self.bytes[index];
    if nchar == 0 {
      // 1st char = 6 MSBs of the first byte.
      self.to_base64_char(byte >> 2)
    } else if nchar == 1 {
      // 2nd char = 2 LSBs of the first byte + 4 MSBs of second byte.
      self.to_base64_char(self.bytes[index - 1] << 4 | byte >> 4)
    } else {
      // 3rd char = 4 LSBs of the second byte + 2 MSBs of third byte.
      self.to_base64_char(self.bytes[index - 1] << 2 | byte >> 6)
    }
  }
}

#[cfg(test)]
mod test {
  use std::iter::FromIterator;

  use HexDecoder;
  use Base64Encoder;

  #[test]
  fn test() {
    let decoder = HexDecoder::new("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
    let bytes = Vec::from_iter(decoder);
    let encoder = Base64Encoder::new(&bytes[..]);
    assert!(String::from_iter(encoder) == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");

    let encoder = Base64Encoder::new("pleasure.".as_bytes());
    assert!(String::from_iter(encoder) == "cGxlYXN1cmUu");

    let encoder = Base64Encoder::new("leasure.".as_bytes());
    assert!(String::from_iter(encoder) == "bGVhc3VyZS4=");

    let encoder = Base64Encoder::new("easure.".as_bytes());
    assert!(String::from_iter(encoder) == "ZWFzdXJlLg==");

    let encoder = Base64Encoder::new("asure.".as_bytes());
    assert!(String::from_iter(encoder) == "YXN1cmUu");

    let encoder = Base64Encoder::new("sure.".as_bytes());
    assert!(String::from_iter(encoder) == "c3VyZS4=");
  }
}
