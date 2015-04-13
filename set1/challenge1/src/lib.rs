use std::iter::FromIterator;

pub trait HexDecoder {
  fn from_hex(&self) -> Vec<u8>;
}

impl HexDecoder for str {
  fn from_hex(&self) -> Vec<u8> {
    fn convert(byte: u8) -> u8 {
      match byte {
        b'a'...b'f' => 10 + byte - b'a',
        b'A'...b'F' => 10 + byte - b'A',
        b'0'...b'9' => byte - b'0',
        _ => panic!("invalid hex character")
      }
    }

    assert!(self.len() % 2 == 0);
    Vec::from_iter(self.as_bytes().chunks(2).map(|chunk| {
      16 * convert(chunk[0]) + convert(chunk[1])
    }))
  }
}

static CHARS: &'static[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

pub trait Base64Encoder {
  fn to_base64(&self) -> String;
}

impl Base64Encoder for [u8] {
  fn to_base64(&self) -> String {
    // Four characters per triple of bytes.
    let mut buf = Vec::with_capacity((self.len() / 3) * 4);

    fn convert(index: u8) -> u8 {
      // Zero the two MSBs.
      CHARS[(index & 0x3f) as usize]
    }

    for chunk in self.chunks(3) {
      let byte1 = chunk[0];
      // Pretend the 2nd byte is zero if there is none.
      let byte2 = if chunk.len() > 1 { chunk[1] } else { 0 };
      // Pretend the 3rd byte is zero if there is none.
      let byte3 = if chunk.len() > 2 { chunk[2] } else { 0 };

      // 1st char = 6 MSBs of the first byte.
      buf.push(convert(byte1 >> 2));

      // 2nd char = 2 LSBs of the first byte + 4 MSBs of second byte.
      buf.push(convert(byte1 << 4 | byte2 >> 4));

      if chunk.len() > 1 {
        // 3rd char = 4 LSBs of the second byte + 2 MSBs of third byte.
        buf.push(convert(byte2 << 2 | byte3 >> 6));
      }

      if chunk.len() == 3 {
        // 4th char = 6 LSBs of the third byte.
        buf.push(convert(byte3));
      }

      // Add padding.
      for _ in 0..3-chunk.len() {
        buf.push(b'=');
      }
    }

    unsafe {
      String::from_utf8_unchecked(buf)
    }
  }
}

#[cfg(test)]
mod test {
  use HexDecoder;
  use Base64Encoder;

  #[test]
  fn test() {
    let bytes = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d".from_hex();
    assert_eq!(bytes.to_base64(), "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");

    assert_eq!(b"pleasure.".to_base64(), "cGxlYXN1cmUu");
    assert_eq!(b"leasure.".to_base64(), "bGVhc3VyZS4=");
    assert_eq!(b"easure.".to_base64(), "ZWFzdXJlLg==");
    assert_eq!(b"asure.".to_base64(), "YXN1cmUu");
    assert_eq!(b"sure.".to_base64(), "c3VyZS4=");
  }
}
