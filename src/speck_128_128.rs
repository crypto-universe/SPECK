use block128::Block128;

const ALPHA:  u32   = 8;
const BETA:   u32   = 3;
const ROUNDS: usize = 32;

#[allow(non_camel_case_types)]
pub struct Speck_128_128 {
	keys_propagated: [u64; ROUNDS]
}

impl Speck_128_128 {
	pub fn new<U: Into<Block128>>(key: U) -> Speck_128_128 {
		let mut key_temp: [u64; ROUNDS] = [0; ROUNDS];
		Speck_128_128::key_schedule(&key.into(), &mut key_temp);
		Speck_128_128 {keys_propagated: key_temp}
	}

	fn key_schedule(key: &Block128, propagated: &mut [u64; ROUNDS]) {
		let mut y1: u64 = key.get_b();
		let mut y2: u64 = key.get_a();
		propagated[0] = key.get_a();
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
	let key: Block128 = Block128::from(0x07060504030201000f0e0d0c0b0a0908);
	let expected_ciphertext = [0x7860fedf5c570d18, 0xa65d985179783265];

	let s: Speck_128_128 = Speck_128_128::new(key);

	let (cypher_a, cypher_b) = s.speck_encrypt(plain_text[0], plain_text[1]);
	assert_eq!([cypher_a, cypher_b], expected_ciphertext);

	let (decr_a, decr_b) = s.speck_decrypt(cypher_a, cypher_b);
	assert_eq!([decr_a, decr_b], plain_text);
}
