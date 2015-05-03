extern crate rand;
extern crate time;
extern crate challenge21;

use rand::{Rng, OsRng, SeedableRng};
use std::thread::sleep_ms;
use challenge21::MT19937RNG;

pub fn rng_unix_time() -> MT19937RNG {
  let mut rng = OsRng::new().unwrap();

  // Sleep 40-1000s before seeding.
  sleep_ms(rng.gen_range(40, 1001) * 1000);

  let mt = MT19937RNG::from_seed(unix_time());

  // Sleep 40-1000s after seeding.
  sleep_ms(rng.gen_range(40, 1001) * 1000);

  mt
}

pub fn unix_time() -> u32 {
  time::get_time().sec as u32
}

#[cfg(test)]
mod test {
  use rand::{Rng, SeedableRng};
  use rng_unix_time;
  use unix_time;
  use challenge21::MT19937RNG;

  #[test]
  fn test() {
    let start = unix_time();
    let mut rng = rng_unix_time();
    let out = rng.next_u32();

    // Try all possible seeds.
    for time in start..unix_time() {
      let mut mt = MT19937RNG::from_seed(time);

      // If the first output is the same we probably found the seed.
      if mt.next_u32() == out {
        return;
      }
    }

    assert!(false);
  }
}
