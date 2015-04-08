extern crate challenge1;
extern crate challenge2;

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::iter::{FromIterator, repeat};
use challenge1::HexDecoder;
use challenge2::XOR;

pub fn find_possible_decryption(hexes: &[&[u8]]) -> Vec<u8> {
  let mut heap = BinaryHeap::new();

  for hex in hexes {
    let decoder = HexDecoder::new(hex);
    let bytes = Vec::from_iter(decoder);

    for candidate in XorCandidates::new(&bytes[..]) {
      heap.push(candidate);
    }
  }

  match heap.pop() {
    Some(candidate) => candidate.bytes,
    None => vec!()
  }
}

struct XorCandidate {
  bytes: Vec<u8>,
  score: usize
}

impl XorCandidate {
  fn new(bytes: Vec<u8>) -> XorCandidate {
    let mut score = 0us;

    fn is_letter(chr: u8) -> bool {
      (chr >= 65 && chr <= 90) || (chr >= 97 && chr <= 122)
    }

    // A text will very likely have more letters than non-letter symbols.
    let num_letters = bytes.iter().filter(|x| is_letter(**x)).count();
    let num_non_letters = bytes.iter().filter(|x| !is_letter(**x)).count();
    score += num_letters / num_non_letters;

    // The number of works seems a good metric.
    score += bytes.split(|chr| *chr == 32u8).count();

    XorCandidate { bytes: bytes, score: score }
  }
}

impl PartialEq for XorCandidate {
  fn eq(&self, other: &XorCandidate) -> bool {
    self.score.eq(&other.score)
  }
}

impl Eq for XorCandidate {}

impl PartialOrd for XorCandidate {
  fn partial_cmp(&self, other: &XorCandidate) -> Option<Ordering> {
    self.score.partial_cmp(&other.score)
  }
}

impl Ord for XorCandidate {
  fn cmp(&self, other: &XorCandidate) -> Ordering {
    self.score.cmp(&other.score)
  }
}

struct XorCandidates<'a> {
  ciphertext: &'a [u8],
  byte: u16
}

impl<'a> XorCandidates<'a> {
  fn new(ct: &'a [u8]) -> XorCandidates<'a> {
    XorCandidates { ciphertext: ct, byte: 0 }
  }
}

impl<'a> Iterator for XorCandidates<'a> {
  type Item = XorCandidate;

  #[inline]
  fn next(&mut self) -> Option<<Self as Iterator>::Item> {
    if self.byte > 255 {
      return None;
    }

    // Construct the current key.
    let key_bytes = repeat(self.byte as u8).take(self.ciphertext.len());
    let key = Vec::from_iter(key_bytes);
    self.byte += 1;

    // Decrypt using the current key.
    let xor = XOR::new(&key[..], self.ciphertext);
    let xor = Vec::from_iter(xor);

    Some(XorCandidate::new(xor))
  }
}

#[cfg(test)]
mod test {
  use find_possible_decryption;

  #[test]
  fn test() {
    let result = find_possible_decryption(&[b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"]);
    let text = String::from_utf8(result).unwrap();
    assert_eq!(text, "Cooking MC's like a pound of bacon");
  }
}
