//   128/128

use block128::Block128;

const ALPHA:   u32 = 8;
const BETA:    u32 = 3;

pub const WORDS_IN_KEY: usize   = 2;
pub const BYTES_IN_KEY: usize   = 16;
pub const ROUNDS:  usize   = 32;

pub struct Speck {
	keys_propagated: [u64; ROUNDS]
}

impl Speck {
	pub fn new(key_b: &Block128) -> Speck{
		let key = [key_b.get_a(), key_b.get_b()];
		let mut key_temp: [u64; ROUNDS] = [0; ROUNDS];
		Speck::key_schedule(&key, &mut key_temp);
		Speck {keys_propagated: key_temp}
	}

	fn key_schedule(key: &[u64; WORDS_IN_KEY], propagated: &mut [u64; ROUNDS]) {
		let mut y1: u64 = key[1];
		let mut y2: u64 = key[0];
		propagated[0] = key[0];
		for (i, item) in &mut propagated.into_iter().enumerate().skip(1) {
			speck_round_forward(&mut y1, &mut y2, &((i-1) as u64));
			(*item) = y2;
		}
	}

	pub fn speck_encrypt(&self, pt: &Block128) -> Block128 {
		let mut plaintext1 = pt.get_a();
		let mut plaintext2 = pt.get_b();

		for curr_key in &self.keys_propagated {
			speck_round_forward(&mut plaintext2, &mut plaintext1, curr_key);
		}

		Block128::new(plaintext1, plaintext2)
	}

	pub fn speck_decrypt(&self, ct: &Block128) -> Block128 {
		let mut ciphertext1 = ct.get_a();
		let mut ciphertext2 = ct.get_b();
		
		for curr_key in self.keys_propagated.into_iter().rev() {
			speck_round_backward(&mut ciphertext2, &mut ciphertext1, curr_key);
		}

		Block128::new(ciphertext1, ciphertext2)
	}
}

#[inline]
fn speck_round_forward(x1: &mut u64, x2: &mut u64, key: &u64) {
	*x1 = ((x1.rotate_right(ALPHA)).wrapping_add(*x2)) ^ key;
	*x2 = x2.rotate_left(BETA) ^ (*x1);
}

#[inline]
fn speck_round_backward(x1: &mut u64, x2: &mut u64, key: &u64) {
	*x2 = (*x2 ^ *x1).rotate_right(BETA);
	*x1 = ((*x1 ^ key).wrapping_sub(*x2)).rotate_left(ALPHA);
}

#[allow(dead_code)]
#[inline]
fn rol(num: u64, amount: u8) -> u64 {
	(num << amount) | (num >> (64-amount))
}

#[allow(dead_code)]
#[inline]
fn ror(num: u64, amount: u8) -> u64 {
	(num >> amount) | (num << (64-amount))
}

#[test]
fn basic_works1() {
	let plain_text: Block128 = Block128::new(0x7469206564616d20, 0x6c61766975716520);
	let key: Block128 = Block128::new(0x0706050403020100, 0x0f0e0d0c0b0a0908);
	let expected_ciphertext = Block128::new(0x7860fedf5c570d18, 0xa65d985179783265);

	let s: Speck = Speck::new(&key);

	let cipher = s.speck_encrypt(&plain_text);
	assert_eq!(cipher, expected_ciphertext);

	let decr = s.speck_decrypt(&cipher);
	assert_eq!(decr, plain_text);
}
