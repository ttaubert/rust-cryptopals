pub trait PKCS7Unpad {
  fn pkcs7_unpad(&self) -> Option<Vec<u8>>;
}

impl PKCS7Unpad for [u8] {
  fn pkcs7_unpad(&self) -> Option<Vec<u8>> {
    let len = self.len();
    if len == 0 {
      return None;
    }

    let pad = self[len - 1] as usize;
    if pad == 0 || pad > len {
      return None;
    }

    if (len-pad..len-1).any(|i| self[i] != self[len - 1]) {
      return None;
    }

    Some(self[..len-pad].to_vec())
  }
}

#[cfg(test)]
mod test {
  use PKCS7Unpad;

  #[test]
  fn test() {
    assert_eq!(b"YELLOW SUBMARINE\x01".pkcs7_unpad(), Some(b"YELLOW SUBMARINE".to_vec()));
    assert_eq!(b"YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10".pkcs7_unpad(), Some(b"YELLOW SUBMARINE".to_vec()));
    assert_eq!(b"YELLOW SUBMARINE\x01".pkcs7_unpad(), Some(b"YELLOW SUBMARINE".to_vec()));
    assert_eq!(b"YELLOW SUBMARINE\x04\x04\x04\x04".pkcs7_unpad(), Some(b"YELLOW SUBMARINE".to_vec()));
    assert_eq!(b"ICE ICE BABY\x04\x04\x04\x04".pkcs7_unpad(), Some(b"ICE ICE BABY".to_vec()));
    assert_eq!(b"\x05\x05\x05\x05\x05".pkcs7_unpad(), Some(b"".to_vec()));
  }

  #[test]
  fn test_fail() {
    assert_eq!(b"ICE ICE BABY\x05\x05\x05\x05".pkcs7_unpad(), None);
    assert_eq!(b"ICE ICE BABY\x01\x02\x03\x04".pkcs7_unpad(), None);
    assert_eq!(b"ICE ICE BABY\xff\xff\xff\xff".pkcs7_unpad(), None);
    assert_eq!(b"\x00".pkcs7_unpad(), None);
    assert_eq!(b"".pkcs7_unpad(), None);
  }
}
