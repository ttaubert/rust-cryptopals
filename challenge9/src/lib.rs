use std::iter::{FromIterator, repeat};

pub trait PKCS7Pad {
  fn pkcs7_pad(&self, len: usize) -> Vec<u8>;
}

impl PKCS7Pad for [u8] {
  fn pkcs7_pad(&self, len: usize) -> Vec<u8> {
    let mut data = self.to_vec();
    let num = len - self.len() % len;
    data.extend(Vec::from_iter(repeat(num as u8).take(num)));
    data
  }
}

#[cfg(test)]
mod test {
  use PKCS7Pad;

  #[test]
  fn test() {
    assert_eq!(b"YELLOW SUBMARINE".pkcs7_pad(1), b"YELLOW SUBMARINE\x01");
    assert_eq!(b"YELLOW SUBMARINE".pkcs7_pad(16), b"YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10");
    assert_eq!(b"YELLOW SUBMARINE".pkcs7_pad(17), b"YELLOW SUBMARINE\x01");
    assert_eq!(b"YELLOW SUBMARINE".pkcs7_pad(20), b"YELLOW SUBMARINE\x04\x04\x04\x04");
  }
}
