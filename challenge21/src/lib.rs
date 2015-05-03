extern crate rand;
extern crate challenge4;

use rand::{Rng, SeedableRng};

const N: usize = 624;
const M: usize = 397;
const MATRIX_A: u32 = 0x9908b0df;   /* constant vector a */
const UPPER_MASK: u32 = 0x80000000; /* most significant w-r bits */
const LOWER_MASK: u32 = 0x7fffffff; /* least significant r bits */

pub struct MT19937RNG {
  state: [u32; N],
  index: usize
}

impl MT19937RNG {
  fn generate(&mut self) {
    for i in 0..N {
      let byte = (self.state[i] & UPPER_MASK) | (self.state[(i + 1) % N] & LOWER_MASK);
      self.state[i] = self.state[(i + M) % N] ^ (byte >> 1);

      if byte % 2 == 1 {
        self.state[i] ^= MATRIX_A;
      }
    }
  }
}

impl SeedableRng<u32> for MT19937RNG {
  fn reseed(&mut self, seed: u32) {
    self.index = 0;
    self.state[0] = seed;

    for i in 1..N {
      let prev = self.state[i - 1] as u64;
      self.state[i] = (0x6c078965 * (prev ^ (prev >> 30)) + i as u64) as u32;
    }
  }

  fn from_seed(seed: u32) -> Self {
    let mut rng = MT19937RNG { index: 0, state: [0; N] };
    rng.reseed(seed);
    rng
  }
}

impl Rng for MT19937RNG {
  fn next_u32(&mut self) -> u32 {
    if self.index == 0 {
      self.generate();
    }

    let mut byte = self.state[self.index];
    byte ^= byte >> 11;
    byte ^= (byte << 7) & 0x9d2c5680;
    byte ^= (byte << 15) & 0xefc60000;
    byte ^= byte >> 18;

    self.index = (self.index + 1) % N;
    byte
  }
}

#[cfg(test)]
mod test {
  use rand::{Rng, SeedableRng};
  use challenge4::read_file;
  use MT19937RNG;

  #[test]
  fn test() {
    let data = read_file("data.txt");
    let numbers = data.split('\n').map(|line| u32::from_str_radix(line, 10));

    let mut rng = MT19937RNG::from_seed(5489);
    for (b, a) in numbers.zip(rng.gen_iter::<u32>().take(1000)) {
      assert_eq!(a, b.unwrap());
    }
  }

  #[test]
  fn test_gen() {
    let data = read_file("gen.txt");
    let numbers = data.split('\n').map(|line| u32::from_str_radix(line, 10));

    let mut rng = MT19937RNG::from_seed(5489);
    rng.next_u32();

    for (a, b) in rng.state.iter().zip(numbers) {
      assert_eq!(*a, b.unwrap());
    }
  }

  #[test]
  fn test_seed() {
    let data = read_file("seed.txt");
    let numbers = data.split('\n').map(|line| u32::from_str_radix(line, 10));

    let rng = MT19937RNG::from_seed(5489);
    for (a, b) in rng.state.iter().zip(numbers) {
      assert_eq!(*a, b.unwrap());
    }
  }

  #[test]
  fn test_same() {
    let mut rng1 = MT19937RNG::from_seed(12345678);
    let mut rng2 = MT19937RNG::from_seed(12345678);

    let out1 = rng1.gen_iter::<u32>();
    let out2 = rng2.gen_iter::<u32>();

    for (a, b) in out1.zip(out2.take(1000)) {
      assert_eq!(a, b);
    }
  }
}
