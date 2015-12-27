//   128/128
#![allow(unused_parens)]

const ALPHA:   u32 = 8;
const BETA:    u32 = 3;
pub const KEY_LEN: usize   = 2;
pub const BLOCK_LEN: usize = 2;
pub const BLOCK_SIZE: usize = 16;
pub const ROUNDS:  usize   = 32;

pub struct Speck {
	keys_propagated: [u64; ROUNDS]
}

impl Speck {
	pub fn new(key: &[u64; KEY_LEN]) -> Speck{
		let mut key_temp: [u64; ROUNDS] = [0; ROUNDS];
		Speck::key_schedule(&key, &mut key_temp);
		Speck {keys_propagated: key_temp}
	}

	fn key_schedule(key: &[u64; KEY_LEN], propagated: &mut [u64; ROUNDS]) {
		let mut y: [u64; KEY_LEN] = [key[1], key[0]];
		propagated[0] = key[0];
		for i in 1..ROUNDS {
			speck_round_forward(&mut y, (i-1) as u64);
			propagated[i] = y[1];
		}
	}

	pub fn speck_encrypt(&self, plaintext: &[u64], result: &mut [u64]) {
		if (plaintext.len() != 2 || result.len() != 2) {
			panic!("Wrong block length! Plaintext len = {0}, result len = {1}.", plaintext.len(), result.len());
		}

		result[0] = plaintext[1];
		result[1] = plaintext[0];

		for i in 0..ROUNDS {
			speck_round_forward(result, self.keys_propagated[i]);
		}

		result.swap(0, 1);
	}

	pub fn speck_decrypt(&self, ciphertext: &[u64], result: &mut [u64]) {
		if (ciphertext.len() != 2 || result.len() != 2) {
			panic!("Wrong block length! Ciphertext len = {0}, result len = {1}.", ciphertext.len(), result.len());
		}

		result[0] = ciphertext[1];
		result[1] = ciphertext[0];

		for i in (0..ROUNDS).rev() {
			speck_round_backward(result, self.keys_propagated[i]);
		}

		result.swap(0, 1);
	}

	pub fn cbc_encrypt(&self, iv: &[u64; BLOCK_LEN], plaintext: &[u64], ciphertext: &mut [u64]) {
		let mut buffer1: [u64; BLOCK_LEN] = [0; BLOCK_LEN];

		buffer1[0] = plaintext[0] ^ iv[0];
		buffer1[1] = plaintext[1] ^ iv[1];
		self.speck_encrypt(&buffer1, &mut ciphertext[0 .. 2]);

//		TODO: Better way, but non-working right now
//		for i in (2..plaintext.len()).step_by(2) {
		for i in (2 .. plaintext.len()).filter(|x| x % 2 == 0) {
			buffer1[0] = plaintext[i]   ^ ciphertext[i-2];
			buffer1[1] = plaintext[i+1] ^ ciphertext[i-1];
			self.speck_encrypt(&buffer1, &mut ciphertext[i .. i + 2]);
		}
	}

	pub fn cbc_decrypt(&self, iv: &[u64; BLOCK_LEN], ciphertext: &[u64], decryptedtext: &mut [u64]) {

		self.speck_decrypt(&ciphertext[0 .. 2], &mut decryptedtext[0 .. 2]);
		decryptedtext[0] ^= iv[0];
		decryptedtext[1] ^= iv[1];

//		TODO: Use step_by in future
		for i in (2 .. ciphertext.len()).filter(|x| x % 2 == 0) {
			self.speck_decrypt(&ciphertext[i .. i + 2], &mut decryptedtext[i .. i + 2]);
			decryptedtext[i]   ^= ciphertext[i-2];
			decryptedtext[i+1] ^= ciphertext[i-1];
		}
	}
}

#[inline(always)]
fn speck_round_forward(x: &mut [u64], key: u64) {
	x[0] = ((x[0].rotate_right(ALPHA)).wrapping_add(x[1])) ^ key;
	x[1] = x[1].rotate_left(BETA) ^ (x[0]);
}

#[inline(always)]
fn speck_round_backward(x: &mut [u64], key: u64) {
	x[1] = (x[1] ^ x[0]).rotate_right(BETA);
	x[0] = ((x[0] ^ key).wrapping_sub(x[1])).rotate_left(ALPHA);
}

#[test]
fn basic_works1() {
	let plain_text: [u64; 2] = [0x7469206564616d20, 0x6c61766975716520];
	let key: [u64; 2] = [0x0706050403020100, 0x0f0e0d0c0b0a0908];

	let s: Speck = Speck::new(&key);

	let mut ciphertext: [u64; 2] = [0; 2];
	s.speck_encrypt(&plain_text, &mut ciphertext);
	assert_eq!(ciphertext[0], 0x7860fedf5c570d18);
	assert_eq!(ciphertext[1], 0xa65d985179783265);

	let mut decryptedtext: [u64; 2] = [0; 2];
	s.speck_decrypt(&ciphertext, &mut decryptedtext);
	assert_eq!(decryptedtext[0], plain_text[0]);
	assert_eq!(decryptedtext[1], plain_text[1]);
}

#[test]
fn cbc_works1() {
	let plain_text: [u64; 2] = [0x7469206564616d20, 0x6c61766975716520];
	let key: [u64; 2] = [0x0706050403020100, 0x0f0e0d0c0b0a0908];
	let iv1: [u64; 2] = [0xAFF92B19D2240A90, 0xDD55C781B2E48BB0];

	let s: Speck = Speck::new(&key);

	let mut ciphertext1: [u64; 2] = [0; 2];
	s.cbc_encrypt(&iv1, &plain_text, &mut ciphertext1);

	let mut decryptedtext1: [u64; 2] = [0; 2];
	s.cbc_decrypt(&iv1, &ciphertext1, &mut decryptedtext1);
	assert_eq!(decryptedtext1[0], plain_text[0]);
	assert_eq!(decryptedtext1[1], plain_text[1]);
}

#[test]
fn cbc_works2() {
	let long_plain_text: [u64; 6] = [0xB6ECC96CEC3EE647, 0x0D698FDCED742594, 0x78BCB34D52D1B961, 0xA03EF56F828A60DE, 0xE725480B83C30B2C, 0xE57669757165C2BA];
	let key: [u64; 2] = [0x0706050403020100, 0x0f0e0d0c0b0a0908];
	let iv2: [u64; 2] = [0xD2C4B7D96C49160E, 0x4EFE0C3E3B9FFD85];

	let s: Speck = Speck::new(&key);

	let mut long_ciphertext: [u64; 6] = [0; 6];
	s.cbc_encrypt(&iv2, &long_plain_text, &mut long_ciphertext);

	let mut long_decryptedtext: [u64; 6] = [0; 6];
	s.cbc_decrypt(&iv2, &long_ciphertext, &mut long_decryptedtext);
	assert_eq!(long_plain_text[0], long_decryptedtext[0]);
	assert_eq!(long_plain_text[1], long_decryptedtext[1]);
	assert_eq!(long_plain_text[2], long_decryptedtext[2]);
	assert_eq!(long_plain_text[3], long_decryptedtext[3]);
	assert_eq!(long_plain_text[4], long_decryptedtext[4]);
	assert_eq!(long_plain_text[5], long_decryptedtext[5]);
}

#[test]
#[should_panic]
fn wrong_block_len_enc_1() {
	let plain_text: [u64; 2] = [0x7469206564616d20, 0x6c61766975716520];
	let mut wrong_ciphertext: [u64; 1] = [0];
	let key: [u64; 2] = [0x0706050403020100, 0x0f0e0d0c0b0a0908];

	let s: Speck = Speck::new(&key);
	s.speck_encrypt(&plain_text, &mut wrong_ciphertext);
}

#[test]
#[should_panic]
fn wrong_block_len_enc_2() {
	let wrong_plain_text: [u64; 1] = [0x7469206564616d20];
	let mut ciphertext: [u64; 2] = [0, 0];
	let key: [u64; 2] = [0x0706050403020100, 0x0f0e0d0c0b0a0908];

	let s: Speck = Speck::new(&key);
	s.speck_encrypt(&wrong_plain_text, &mut ciphertext);
}

#[test]
#[should_panic]
fn wrong_block_len_enc_3() {
	let wrong_plain_text: [u64; 1] = [0x7469206564616d20];
	let mut wrong_ciphertext: [u64; 1] = [0];
	let key: [u64; 2] = [0x0706050403020100, 0x0f0e0d0c0b0a0908];

	let s: Speck = Speck::new(&key);
	s.speck_encrypt(&wrong_plain_text, &mut wrong_ciphertext);
}
