extern crate challenge2;
extern crate challenge6;
extern crate challenge10;

use std::iter::FromIterator;
use std::mem;
use challenge2::Xor;
use challenge10::aes_128_ecb_encrypt;

pub fn aes_128_ctr_transform(key: &[u8], nonce: u64, plaintext: &[u8]) -> Vec<u8> {
  let mut iv = [nonce.to_le(), 0u64];
  let num_blocks = (plaintext.len() as u64 / 16) + 1;

  let keystream = (0u64..num_blocks).flat_map(|counter| {
    iv[1] = counter.to_le();
    let buf: [u8; 16] = unsafe { mem::transmute(iv) };
    aes_128_ecb_encrypt(key, &buf).into_iter()
  });

  plaintext.xor(&Vec::from_iter(keystream))
}

#[cfg(test)]
mod test {
  use challenge6::Base64Decoder;
  use aes_128_ctr_transform;

  #[test]
  fn test() {
    let data = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==".from_base64();
    let key = b"YELLOW SUBMARINE";
    let nonce = 0u64;

    let decrypted = aes_128_ctr_transform(key, nonce, &data);
    assert_eq!(String::from_utf8(decrypted).unwrap(), "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ");
  }
}
