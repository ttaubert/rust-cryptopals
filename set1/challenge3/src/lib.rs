extern crate challenge1;
extern crate challenge2;

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::iter::{FromIterator, repeat};
use challenge1::HexDecoder;
use challenge2::Xor;

pub fn find_decryption<F>(ciphertexts: &[&str], scoring_fun: F) -> Vec<u8>
    where F: Fn(&[u8]) -> usize
{
  let mut heap = BinaryHeap::new();

  for ciphertext in ciphertexts.iter().map(|ct| ct.from_hex()) {
    // Try all 256 possible keys.
    for byte in 0us..256 {
      // Construct the current key.
      let key = Vec::from_iter(repeat(byte as u8).take(ciphertext.len()));

      // Decrypt using the current key and score.
      let decryption = ciphertext.xor(&key[..]);
      let score = scoring_fun(&decryption[..]);

      // Put into the max heap.
      heap.push(Candidate { bytes: decryption, score: score });
    }
  }

  // Return the decryption of the highest-scoring candidate.
  heap.pop().expect("no ciphertexts given").bytes
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

struct Candidate {
  bytes: Vec<u8>,
  score: usize
}

impl PartialEq for Candidate {
  fn eq(&self, other: &Candidate) -> bool {
    self.score.eq(&other.score)
  }
}

impl Eq for Candidate {}

impl PartialOrd for Candidate {
  fn partial_cmp(&self, other: &Candidate) -> Option<Ordering> {
    self.score.partial_cmp(&other.score)
  }
}

impl Ord for Candidate {
  fn cmp(&self, other: &Candidate) -> Ordering {
    self.score.cmp(&other.score)
  }
}

#[cfg(test)]
mod test {
  use find_decryption;
  use score_text_structure;

  #[test]
  fn test() {
    let ciphertexts = ["1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"];
    let decrypted = find_decryption(&ciphertexts, score_text_structure);
    assert_eq!(String::from_utf8(decrypted).unwrap(), "Cooking MC's like a pound of bacon");
  }
}
