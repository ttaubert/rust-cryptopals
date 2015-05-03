extern crate rand;
extern crate challenge6;
extern crate challenge18;

use rand::{Rng, OsRng};
use std::iter::FromIterator;
use challenge6::{Base64Decoder, find_repeated_xor_decryption_for_keysize};
use challenge18::aes_128_ctr_transform;

static SECRETS: [&'static str; 40] = [
  "SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
  "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
  "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
  "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
  "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
  "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
  "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
  "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
  "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
  "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
  "VG8gcGxlYXNlIGEgY29tcGFuaW9u",
  "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
  "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
  "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
  "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
  "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
  "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
  "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
  "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
  "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
  "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
  "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
  "U2hlIHJvZGUgdG8gaGFycmllcnM/",
  "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
  "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
  "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
  "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
  "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
  "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
  "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
  "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
  "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
  "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
  "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
  "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
  "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
  "SW4gdGhlIGNhc3VhbCBjb21lZHk7",
  "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
  "VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
  "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4="
];

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

  pub fn encrypt(&self) -> Vec<Vec<u8>> {
    Vec::from_iter(SECRETS.iter().map(|secret| {
      // Encrypt all secrets with the same nonce = 0.
      aes_128_ctr_transform(&self.key, 0u64, &secret.from_base64())
    }))
  }
}

pub fn recover_plaintexts(cts: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
  // Find the length of the shortest ciphertext.
  let min_len = cts.iter().map(|ct| ct.len()).min().unwrap();

  // Grab |min_len| bytes of each ciphertext and concat them.
  let concat = Vec::from_iter(cts.into_iter().flat_map(|ct| {
    ct.into_iter().take(min_len)
  }));

  // Treat the concatenated buffer as a repeated XOR encryption with a key of
  // size |min_len| bytes. We'll put bytes at the same indexes in buckets and
  // try to find the key byte by scoring candidates based on text structure.
  let (blocks, _) = find_repeated_xor_decryption_for_keysize(&concat, min_len);

  // Slice the concatenated buffer back into blocks of length |min_len|.
  Vec::from_iter(blocks.chunks(min_len).map(|chunk| {
    Vec::from_iter(chunk.iter().map(|b| *b))
  }))
}

#[cfg(test)]
mod test {
  use BlackBox;
  use recover_plaintexts;

  #[test]
  fn test() {
    let blackbox = BlackBox::new();
    let ciphertexts = blackbox.encrypt();
    let plaintexts = recover_plaintexts(ciphertexts);

    // Check parts of some of the plaintexts. We didn't really
    // recover all of the plaintext but that should be enough
    // to consider it completely broken.
    let expected = b" have met them at c";
    assert_eq!(&plaintexts[0][1..expected.len()+1], expected);

    let expected = b"oming with vivid fa";
    assert_eq!(&plaintexts[1][1..expected.len()+1], expected);

    let expected = b" terrible beauty is";
    assert_eq!(&plaintexts[39][1..expected.len()+1], expected);
  }
}
