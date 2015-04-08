extern crate challenge3;

use std::fs::File;
use std::io::Read;

pub fn read_file(path: &str) -> Vec<u8> {
  let mut bytes = Vec::new();
  match File::open(path).and_then(|mut f| f.read_to_end(&mut bytes)) {
    Ok(_) => bytes,
    Err(_) => panic!("error opening file")
  }
}

#[cfg(test)]
mod test {
  use std::iter::FromIterator;
  use challenge3::find_possible_decryption;
  use read_file;

  #[test]
  fn test() {
    let data = read_file("data.txt");
    let lines = Vec::from_iter(data.split(|b| *b == '\n' as u8));
    let result = find_possible_decryption(&lines[..]);
    let text = String::from_utf8(result).unwrap();
    assert_eq!(text, "Now that the party is jumping\n");
  }
}
