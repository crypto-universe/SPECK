//   128/128

const ALPHA:   u32 = 8;
const BETA:    u32 = 3;

pub const WORDS_IN_KEY: usize   = 2;
pub const BYTES_IN_KEY: usize   = 16;
pub const ROUNDS:  usize   = 32;

pub struct Speck {
	keys_propagated: [u64; ROUNDS]
}

//TODO: Use Block128 type with u128 (unstable now) inside
impl Speck {
	pub fn new(key: &[u64; WORDS_IN_KEY]) -> Speck{
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

	pub fn speck_encrypt(&self, mut plaintext1: u64, mut plaintext2: u64) -> (u64, u64) {

		for curr_key in &self.keys_propagated {
			speck_round_forward(&mut plaintext2, &mut plaintext1, curr_key);
		}

		(plaintext1, plaintext2)
	}

	pub fn speck_decrypt(&self, mut ciphertext1: u64, mut ciphertext2: u64) -> (u64, u64) {

		for curr_key in self.keys_propagated.into_iter().rev() {
			speck_round_backward(&mut ciphertext2, &mut ciphertext1, curr_key);
		}

		(ciphertext1, ciphertext2)
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

#[test]
fn basic_works1() {
	let plain_text: [u64; 2] = [0x7469206564616d20, 0x6c61766975716520];
	let key: [u64; 2] = [0x0706050403020100, 0x0f0e0d0c0b0a0908];
	let expected_ciphertext = [0x7860fedf5c570d18, 0xa65d985179783265];

	let s: Speck = Speck::new(&key);

	let (cypher_a, cypher_b) = s.speck_encrypt(plain_text[0], plain_text[1]);
	assert_eq!([cypher_a, cypher_b], expected_ciphertext);

	let (decr_a, decr_b) = s.speck_decrypt(cypher_a, cypher_b);
	assert_eq!([decr_a, decr_b], plain_text);
}
