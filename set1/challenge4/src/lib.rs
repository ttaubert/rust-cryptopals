extern crate challenge1;
extern crate challenge3;

use std::fs::File;
use std::io::Read;

pub fn read_file(path: &str) -> String {
  let mut file = File::open(path).ok().expect("error opening file");

  let mut data = String::new();
  file.read_to_string(&mut data).ok().expect("error reading file");

  data
}

#[cfg(test)]
mod test {
  use std::iter::FromIterator;
  use challenge1::HexDecoder;
  use challenge3::find_decryption;
  use read_file;

  #[test]
  fn test() {
    let data = read_file("data.txt");
    let lines = Vec::from_iter(data.split('\n').map(|line| line.from_hex()));
    let (_, decrypted) = find_decryption(&lines[..]);
    assert_eq!(String::from_utf8(decrypted).unwrap(), "Now that the party is jumping\n");
  }
}
