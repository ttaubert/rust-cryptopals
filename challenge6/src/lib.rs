extern crate challenge1;
extern crate challenge3;
extern crate challenge4;
extern crate challenge5;

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::iter::FromIterator;
use challenge3::{find_decryption, score_text_structure};
use challenge5::RepeatedXor;

pub fn find_repeated_xor_decryption(data: &[u8], num_tries: usize) -> Vec<u8> {
  let mut heap = BinaryHeap::with_capacity(num_tries);

  // Try various key sizes and take the |num_tries| best ones.
  for size in rank_xor_keysizes(data).iter().take(num_tries) {
    let bytes = find_repeated_xor_decryption_for_keysize(data, *size);
    let score = score_text_structure(&bytes);
    heap.push(CandidateDecryption { bytes: bytes, score: score });
  }

  heap.pop().expect("no decryption candidates?").bytes
}

pub fn find_repeated_xor_decryption_for_keysize(data: &[u8], key_size: usize) -> Vec<u8> {
  // Cut the text into |size| blocks.
  let blocks = cut_into_blocks(data, key_size);

  // Determine the most likely key for each block.
  let key = Vec::from_iter(blocks.into_iter().map(|block| {
    find_decryption(&[block]).0
  }));

  // Decrypt.
  data.xor_repeat(&key)
}

struct CandidateDecryption {
  bytes: Vec<u8>,
  score: usize
}

impl PartialEq for CandidateDecryption {
  fn eq(&self, other: &CandidateDecryption) -> bool {
    self.score.eq(&other.score)
  }
}

impl Eq for CandidateDecryption {}

impl PartialOrd for CandidateDecryption {
  fn partial_cmp(&self, other: &CandidateDecryption) -> Option<Ordering> {
    self.score.partial_cmp(&other.score)
  }
}

impl Ord for CandidateDecryption {
  fn cmp(&self, other: &CandidateDecryption) -> Ordering {
    self.score.cmp(&other.score)
  }
}

fn rank_xor_keysizes(bytes: &[u8]) -> Vec<usize> {
  assert!(bytes.len() >= 3 * 40);
  let mut heap = BinaryHeap::with_capacity(39);

  for len in 2..41 {
    let block1 = &bytes[..len];
    let block2 = &bytes[len..len*2];
    let block3 = &bytes[len*2..len*3];

    // Compute hamming distances.
    let mut dist = block1.hamming_distance(block2);
    dist += block2.hamming_distance(block3);
    dist += block1.hamming_distance(block3);

    // Average the distances and put into heap.
    heap.push(CandidateKeySize { size: len, distance: dist / len * 3 });
  }

  // Convert into sorted vec, more likely keysizes first.
  Vec::from_iter((0..heap.len()).map(|_| heap.pop().unwrap().size))
}

struct CandidateKeySize {
  size: usize,
  distance: usize
}

impl PartialEq for CandidateKeySize {
  fn eq(&self, other: &CandidateKeySize) -> bool {
    self.distance.eq(&other.distance)
  }
}

impl Eq for CandidateKeySize {}

impl PartialOrd for CandidateKeySize {
  fn partial_cmp(&self, other: &CandidateKeySize) -> Option<Ordering> {
    self.distance.partial_cmp(&other.distance).map(|o| o.reverse())
  }
}

impl Ord for CandidateKeySize {
  fn cmp(&self, other: &CandidateKeySize) -> Ordering {
    self.distance.cmp(&other.distance).reverse()
  }
}

pub trait HammingDistance<T> {
  fn hamming_distance(&self, other: T) -> usize;
}

impl<'a> HammingDistance<&'a [u8]> for [u8] {
  fn hamming_distance(&self, other: &'a [u8]) -> usize {
    self.iter().zip(other.iter()).fold(0, |dist, (a, b)| {
      dist + (a ^ b).count_ones() as usize
    })
  }
}

fn cut_into_blocks(data: &[u8], blocksize: usize) -> Vec<Vec<u8>> {
  let mut blocks = Vec::with_capacity(blocksize);

  // Prepare the blocks.
  for _ in 0..blocksize {
    blocks.push(Vec::with_capacity(data.len() / blocksize + 1));
  }

  // Put data in the right buckets.
  for (i, byte) in data.iter().enumerate() {
    blocks[i % blocksize].push(*byte);
  }

  blocks
}

pub trait Base64Decoder {
  fn from_base64(&self) -> Vec<u8>;
}

impl Base64Decoder for str {
  fn from_base64(&self) -> Vec<u8> {
    fn convert(byte: u8) -> u8 {
      match byte {
        b'A'...b'Z' => byte - b'A',
        b'a'...b'z' => 26 + byte - b'a',
        b'0'...b'9' => 52 + byte - b'0',
        b'+' => 62,
        b'/' => 63,
        _ => panic!("invalid base64 character")
      }
    }

    assert!(self.len() % 4 == 0);
    // Four characters per triple of bytes.
    let mut buf = Vec::with_capacity((self.len() / 4) * 3);

    for chunk in self.as_bytes().chunks(4) {
      let char1 = convert(chunk[0]);
      let char2 = convert(chunk[1]);

      // 1st byte = all 6 bits of the first char + 2 MSBs of the second char
      buf.push(char1 << 2 | char2 >> 4);

      // 2nd or 3rd byte might be missing so we have to watch for padding.
      if chunk[2] != b'=' {
        let char3 = convert(chunk[2]);

        // 2nd byte = 4 LSBs of the second char + 4 MSBs of the third char
        buf.push(char2 << 4 | char3 >> 2);

        if chunk[3] != b'=' {
          let char4 = convert(chunk[3]);

          // 3nd byte = 2 LSBs of the third char + all 6 bits of the fourth char
          buf.push(char3 << 6 | char4);
        }
      }

      // Stop when we reach the padding.
      if chunk[2] == b'=' || chunk[3] == b'=' {
        break;
      }
    }

    buf
  }
}

#[cfg(test)]
mod test {
  use challenge1::Base64Encoder;
  use challenge4::read_file;
  use find_repeated_xor_decryption;
  use HammingDistance;
  use Base64Decoder;

  #[test]
  fn test() {
    let data = read_file("data.txt").replace("\n", "").from_base64();
    let decryption = find_repeated_xor_decryption(&data, 3);
    let decryption = String::from_utf8(decryption).unwrap();
    assert!(decryption.starts_with("I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me"));
  }

  #[test]
  fn test_hamming_distance() {
    assert_eq!(b"this is a test".hamming_distance(b"wokka wokka!!!"), 37);
  }

  #[test]
  fn test_base64_decoder() {
    for data in &["pleasure.", "leasure.", "easure.", "asure.", "sure."] {
      let bytes = data.as_bytes();
      assert_eq!(bytes.to_base64().from_base64(), bytes);
    }
  }

  #[test]
  fn test_read_file() {
    let data = read_file("data.txt").replace("\n", "");
    assert!(data.starts_with("HUIfTQsPAh9PE048GmllH0kcDk4TAQsHThsBFkU2AB4BSWQgVB0dQzNTTmVSBgBHVBwNRU0HBAxTEjwMHghJGgkRTxRMIRpHKwAFHUdZEQQJAGQmB1MANxYG"));
  }
}
