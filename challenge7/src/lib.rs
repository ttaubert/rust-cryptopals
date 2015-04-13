extern crate openssl;
extern crate challenge4;
extern crate challenge6;

use openssl::crypto::symm as cipher;

pub fn aes_128_ecb_decrypt(key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
  let cipher = cipher::Crypter::new(cipher::Type::AES_128_ECB);
  cipher.init(cipher::Mode::Decrypt, key, vec!());
  cipher.pad(false);

  let mut decrypted = cipher.update(ciphertext);
  decrypted.extend(cipher.finalize().into_iter());
  decrypted
}

#[cfg(test)]
mod test {
  use challenge4::read_file;
  use challenge6::Base64Decoder;
  use aes_128_ecb_decrypt;

  #[test]
  fn test() {
    let data = read_file("data.txt").replace("\n", "").from_base64();
    let bytes = aes_128_ecb_decrypt(b"YELLOW SUBMARINE", &data[..]);
    let plaintext = String::from_utf8(bytes).unwrap();
    assert!(plaintext.starts_with("I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me"));
  }
}
