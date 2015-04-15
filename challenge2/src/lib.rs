extern crate challenge1;

use std::iter::FromIterator;

pub trait Xor {
  fn xor(&self, other: &[u8]) -> Vec<u8>;
}

impl Xor for [u8] {
  fn xor(&self, other: &[u8]) -> Vec<u8> {
    Vec::from_iter(self.iter().zip(other.iter()).map(|(a, b)| a ^ b))
  }
}

static CHARS: &'static[u8] = b"0123456789abcdef";

pub trait HexEncoder {
  fn to_hex(&self) -> String;
}

impl HexEncoder for [u8] {
  fn to_hex(&self) -> String {
    let mut buf = Vec::with_capacity(self.len() * 2);

    for byte in self {
      buf.push(CHARS[(byte / 16) as usize]);
      buf.push(CHARS[(byte % 16) as usize]);
    }

    unsafe {
      String::from_utf8_unchecked(buf)
    }
  }
}

#[cfg(test)]
mod test {
  use challenge1::HexDecoder;
  use HexEncoder;
  use Xor;

  #[test]
  fn test() {
    let data1 = "1c0111001f010100061a024b53535009181c".from_hex();
    let data2 = "686974207468652062756c6c277320657965".from_hex();
    let xored = data1.xor(&data2);
    assert_eq!(xored.to_hex(), "746865206b696420646f6e277420706c6179");
  }
}
