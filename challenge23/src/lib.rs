extern crate rand;
extern crate challenge21;

use rand::{Rng, OsRng, SeedableRng};
use challenge21::MT19937RNG;

pub fn rng_random() -> MT19937RNG {
  let mut rng = OsRng::new().unwrap();
  MT19937RNG::from_seed(rng.next_u32())
}

pub fn clone_mt19937_rng(rng: &mut MT19937RNG) -> MT19937RNG {
  let mut state = [0; 624];

  for (i, word) in rng.gen_iter::<u32>().take(624).enumerate() {
    let mut word = word;

    // Untemper.
    word ^= word >> 18;
    word ^= (word << 15) & 0xefc60000;

    // word ^= (word << 7) & 0x9d2c5680;
    let mut tmp = word ^ (word << 7) & 0x9d2c5680;
    tmp = word ^ (tmp << 7) & 0x9d2c5680;
    tmp = word ^ (tmp << 7) & 0x9d2c5680;
    word ^= (tmp << 7) & 0x9d2c5680;

    // word ^= word >> 11;
    let tmp = word ^ (word >> 11);
    word ^= tmp >> 11;

    state[i] = word;
  }

  MT19937RNG::from_state(state)
}

#[cfg(test)]
mod test {
  use rand::{Rng};
  use rng_random;
  use clone_mt19937_rng;

  #[test]
  fn test() {
    let mut rng = rng_random();
    let mut clone = clone_mt19937_rng(&mut rng);

    let out1 = rng.gen_iter::<u32>();
    let out2 = clone.gen_iter::<u32>();

    for (a, b) in out1.zip(out2.take(1000)) {
      assert_eq!(a, b);
    }
  }
}
