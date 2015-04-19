extern crate openssl;
extern crate rand;
extern crate challenge9;
extern crate challenge10;

use openssl::crypto::symm as cipher;
use rand::{Rng, OsRng};
use std::collections::HashMap;
use std::iter::FromIterator;
use challenge9::PKCS7Pad;
use challenge10::aes_128_ecb_encrypt;

pub fn aes_128_ecb_decrypt(key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
  assert!(key.len() == 16 && ciphertext.len() % 16 == 0);

  let cipher = cipher::Crypter::new(cipher::Type::AES_128_ECB);
  cipher.init(cipher::Mode::Decrypt, key, vec!());

  let mut decrypted = cipher.update(ciphertext);
  decrypted.extend(cipher.finalize().into_iter());
  decrypted
}

pub struct BlackBox {
  key: [u8; 16]
}

impl BlackBox {
  pub fn new() -> BlackBox {
    let mut rng = OsRng::new().unwrap();

    // Generate a random key.
    let mut key = [0u8; 16];
    rng.fill_bytes(&mut key);

    BlackBox { key: key }
  }

  pub fn profile_for(&self, email: &str) -> Vec<u8> {
    // Remove meta chars.
    let email = email.replace("&", "");
    let email = email.replace("=", "");

    // Encode.
    let encoded = format!("email={}&uid=10&role=user", email);

    // Pad to block size.
    let data = encoded.as_bytes().pkcs7_pad(16);

    // Encrypt.
    aes_128_ecb_encrypt(&self.key, &data)
  }

  pub fn decode(&self, profile: &[u8]) -> HashMap<String,String> {
    let data = aes_128_ecb_decrypt(&self.key, profile);
    let encoded = String::from_utf8(data).unwrap();
    let mut map = HashMap::new();

    for pair in encoded.split("&") {
      let pair = Vec::from_iter(pair.split("="));
      if pair.len() == 2 {
        map.insert(pair[0].to_string(), pair[1].to_string());
      }
    }

    map
  }
}

#[cfg(test)]
mod test {
  use BlackBox;

  #[test]
  fn test() {
    let blackbox = BlackBox::new();

    // 1st: email=asdf@asdf. (X)
    // 2nd: com&uid=10&role= (X)
    let mut profile = blackbox.profile_for("asdf@asdf.com")[..32].to_vec();

    // 1st: email=asdf@asdf.
    // 2nd: adminPPPPPPPPPPP (X)
    let input = "asdf@asdf.admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
    profile.extend(blackbox.profile_for(input)[16..32].to_vec());

    // See if we have a role=admin profile.
    let data = blackbox.decode(&profile);
    assert_eq!(data.get("email").unwrap(), &"asdf@asdf.com");
    assert_eq!(data.get("uid").unwrap(), &"10");
    assert_eq!(data.get("role").unwrap(), &"admin");
  }

  #[test]
  fn test_profile() {
    let blackbox = BlackBox::new();
    let profile = blackbox.profile_for("test@example.com");

    let data = blackbox.decode(&profile);
    assert_eq!(data.get("email").unwrap(), &"test@example.com");
    assert_eq!(data.get("uid").unwrap(), &"10");
    assert_eq!(data.get("role").unwrap(), &"user");
  }

  #[test]
  fn test_meta_chars() {
    let blackbox = BlackBox::new();
    let profile = blackbox.profile_for("test@example.com&role=admin");

    let data = blackbox.decode(&profile);
    assert_eq!(data.get("role").unwrap(), &"user");
  }
}
