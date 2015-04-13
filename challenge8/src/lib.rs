extern crate challenge4;

use std::collections::HashSet;

pub fn find_ecb_ciphertext<'a>(ciphertexts: &[&'a str]) -> &'a str {
  let blocksize = 16 * 2;

  for ciphertext in ciphertexts {
    assert!(ciphertext.len() % blocksize == 0);
    let mut blocks = HashSet::new();

    for i in 0..ciphertext.len() / blocksize {
      let block = &ciphertext[i * blocksize..(i + 1) * blocksize];

      // Did we find a duplicate ciphertext block?
      if blocks.contains(block) {
        return ciphertext;
      }

      blocks.insert(block);
    }
  }

  ""
}

#[cfg(test)]
mod test {
  use std::iter::FromIterator;
  use challenge4::read_file;
  use find_ecb_ciphertext;

  #[test]
  fn test() {
    let data = read_file("data.txt");
    let ciphertexts = Vec::from_iter(data.split('\n'));
    assert_eq!(find_ecb_ciphertext(&ciphertexts[..]), "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a");

  }
}
