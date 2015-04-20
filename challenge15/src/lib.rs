pub trait PKCS7Unpad {
  fn pkcs7_unpad(&self) -> Vec<u8>;
}

impl PKCS7Unpad for [u8] {
  fn pkcs7_unpad(&self) -> Vec<u8> {
    let len = self.len();
    let pad = self[len - 1] as usize;

    if (len-pad..len-1).any(|i| self[i] != self[len - 1]) {
      panic!("invalid padding");
    }

    self[..len-pad].to_vec()
  }
}

#[cfg(test)]
mod test {
  use PKCS7Unpad;

  #[test]
  fn test() {
    assert_eq!(b"YELLOW SUBMARINE\x01".pkcs7_unpad(), b"YELLOW SUBMARINE");
    assert_eq!(b"YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10".pkcs7_unpad(), b"YELLOW SUBMARINE");
    assert_eq!(b"YELLOW SUBMARINE\x01".pkcs7_unpad(), b"YELLOW SUBMARINE");
    assert_eq!(b"YELLOW SUBMARINE\x04\x04\x04\x04".pkcs7_unpad(), b"YELLOW SUBMARINE");
    assert_eq!(b"ICE ICE BABY\x04\x04\x04\x04".pkcs7_unpad(), b"ICE ICE BABY");
  }

  #[test]
  #[should_panic]
  fn test_fail1() {
    b"ICE ICE BABY\x05\x05\x05\x05".pkcs7_unpad();
  }

  #[test]
  #[should_panic]
  fn test_fail2() {
    b"ICE ICE BABY\x01\x02\x03\x04".pkcs7_unpad();
  }

  #[test]
  #[should_panic]
  fn test_fail3() {
    b"ICE ICE BABY\xff\xff\xff\xff".pkcs7_unpad();
  }

  #[test]
  #[should_panic]
  fn test_fail4() {
    b"".pkcs7_unpad();
  }
}
