extern crate challenge1;
extern crate challenge2;

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::iter::{FromIterator, repeat};
use challenge2::Xor;

pub fn find_decryption(ciphertexts: &[Vec<u8>]) -> (u8, Vec<u8>) {
  let mut heap = BinaryHeap::with_capacity(256 * ciphertexts.len());

  for ciphertext in ciphertexts {
    // Try all 256 possible keys.
    for byte in 0us..256 {
      // Construct the current key.
      let key = Vec::from_iter(repeat(byte as u8).take(ciphertext.len()));

      // Decrypt using the current key and score.
      let decryption = ciphertext.xor(&key);
      let score = score_text_structure(&decryption);

      // Put into the max heap.
      heap.push(CandidateKey { key: byte as u8, bytes: decryption, score: score });
    }
  }

  // Return the decryption of the highest-scoring candidate.
  let best = heap.pop().expect("no ciphertexts given");
  (best.key, best.bytes)
}

pub fn score_text_structure(bytes: &[u8]) -> usize {
  let mut score = 0us;

  fn is_letter(chr: u8) -> bool {
    (chr >= 65 && chr <= 90) || (chr >= 97 && chr <= 122)
  }

  // A text will very likely have more letters than non-letter symbols.
  let num_letters = bytes.iter().filter(|x| is_letter(**x)).count();
  let num_non_letters = bytes.len() - num_letters;
  score += num_letters / num_non_letters;

  // The number of words seems a good metric too.
  score + bytes.split(|byte| *byte == 32u8).count()
}

struct CandidateKey {
  key: u8,
  bytes: Vec<u8>,
  score: usize
}

impl PartialEq for CandidateKey {
  fn eq(&self, other: &CandidateKey) -> bool {
    self.score.eq(&other.score)
  }
}

impl Eq for CandidateKey {}

impl PartialOrd for CandidateKey {
  fn partial_cmp(&self, other: &CandidateKey) -> Option<Ordering> {
    self.score.partial_cmp(&other.score)
  }
}

impl Ord for CandidateKey {
  fn cmp(&self, other: &CandidateKey) -> Ordering {
    self.score.cmp(&other.score)
  }
}

#[cfg(test)]
mod test {
  use challenge1::HexDecoder;
  use find_decryption;

  #[test]
  fn test() {
    let ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".from_hex();
    let (_, decrypted) = find_decryption(&[ciphertext]);
    assert_eq!(String::from_utf8(decrypted).unwrap(), "Cooking MC's like a pound of bacon");
  }
}
