//   128/128
#![allow(unused_parens)]

const ALPHA:   u32 = 8;
const BETA:    u32 = 3;
pub const BYTES_IN_WORD: usize = 8;
pub const WORDS_IN_KEY: usize   = 2;
pub const BYTES_IN_KEY: usize   = 16;
pub const WORDS_IN_BLOCK: usize = 2;
pub const BYTES_IN_BLOCK: usize = 16;
pub const ROUNDS:  usize   = 32;

pub struct Speck {
	keys_propagated: [u64; ROUNDS]
}

impl Speck {
	pub fn new(key: &[u64; WORDS_IN_KEY]) -> Speck{
		let mut key_temp: [u64; ROUNDS] = [0; ROUNDS];
		Speck::key_schedule(&key, &mut key_temp);
		Speck {keys_propagated: key_temp}
	}

	//TODO: Make loop pretty
	fn key_schedule(key: &[u64; WORDS_IN_KEY], propagated: &mut [u64; ROUNDS]) {
		let mut y1: u64 = key[1];
		let mut y2: u64 = key[0];
		propagated[0] = key[0];
		for i in 1..ROUNDS {
			speck_round_forward(&mut y1, &mut y2, &((i-1) as u64));
			propagated[i] = y2;
		}
	}

	fn speck_encrypt(&self, plaintext1: u64, plaintext2: u64) -> (u64, u64) {
		let mut a = plaintext2;
		let mut b = plaintext1;

		for curr_key in &self.keys_propagated {
			speck_round_forward(&mut a, &mut b, curr_key);
		}

		(b, a)
	}

	fn speck_decrypt(&self, ciphertext1: u64, ciphertext2: u64) -> (u64, u64) {
		let mut a = ciphertext2;
		let mut b = ciphertext1;

		for curr_key in self.keys_propagated.into_iter().rev() {
			speck_round_backward(&mut a, &mut b, curr_key);
		}

		(b, a)
	}

	pub fn cbc_encrypt_blocks(&self, iv: &[u64; WORDS_IN_BLOCK], plaintext: &Vec<u64>) -> Vec<u64> {
		assert!(!plaintext.is_empty(), "Input plaintext should not be empty!");
		assert!(plaintext.len() % WORDS_IN_BLOCK == 0, "Input buffer has odd length {0}!", plaintext.len());

		let mut ciphertext: Vec<u64> = Vec::with_capacity(plaintext.len()/BYTES_IN_WORD+2);

		let (a, b) = self.speck_encrypt(plaintext[0] ^ iv[0], plaintext[1] ^ iv[1]);
		ciphertext.push(a);
		ciphertext.push(b);

//		TODO: Better way, but non-working right now
//		for i in (2..plaintext.len()).step_by(2) {
		for i in (2 .. plaintext.len()).filter(|x| x % 2 == 0) {
			let (c, d) = self.speck_encrypt(plaintext[i] ^ ciphertext[i-2], plaintext[i+1] ^ ciphertext[i-1]);
			ciphertext.push(c);
			ciphertext.push(d);
		}

		ciphertext
	}

	pub fn cbc_decrypt_blocks(&self, iv: &[u64; WORDS_IN_BLOCK], ciphertext: &Vec<u64>) -> Vec<u64> {
		assert!(!ciphertext.is_empty(), "Input ciphertext should not be empty!");
		assert!(ciphertext.len() % WORDS_IN_BLOCK == 0, "Input buffer has odd length {0}!", ciphertext.len());

		let mut decryptedtext: Vec<u64> = Vec::with_capacity(ciphertext.len()/BYTES_IN_WORD+2);

		let (a, b) = self.speck_decrypt(ciphertext[0], ciphertext[1]);
		decryptedtext.push(a ^ iv[0]);
		decryptedtext.push(b ^ iv[1]);

//		TODO: Use step_by in future
		for i in (2 .. ciphertext.len()).filter(|x| x % 2 == 0) {
			let (c, d) = self.speck_decrypt(ciphertext[i], ciphertext[i+1]);
			decryptedtext.push(c ^ ciphertext[i-2]);
			decryptedtext.push(d ^ ciphertext[i-1]);
		}

		decryptedtext
	}

	//Consider no padding for now
	pub fn cbc_encrypt_byte_array(&self, iv: &[u8; BYTES_IN_BLOCK], plaintext: Vec<u8>)/* -> Vec<u8> */{
		assert!(!plaintext.is_empty(), "Input some text to encrypt.");

		//TODO: Some padding here!
		let iv2: Vec<u64> = bytes_to_words(iv);
		let plaintext2: Vec<u64> = bytes_to_words(plaintext);
		let ciphertext: Vec<u64> = self.cbc_encrypt_blocks(&[iv2[0], iv2[1]], &plaintext2);
	}
}

fn bytes_to_words(input: &[u8]) -> Vec<u64>{
	input.chunks(8).map(|chunk| unsafe {*(chunk.as_ptr() as (*const u64))}).collect::<Vec<u64>>()
}

#[inline(always)]
fn speck_round_forward(x1: &mut u64, x2: &mut u64, key: &u64) {
	*x1 = ((x1.rotate_right(ALPHA)).wrapping_add(*x2)) ^ key;
	*x2 = x2.rotate_left(BETA) ^ (*x1);
}

#[inline(always)]
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

	//let key2: [u8; 16] = [07, 06, 05, 04, 03, 02, 01, 00, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08];
	//assert!(bytes_to_words(&key2).len() == 2, "{}", bytes_to_words(&key2).len());
}

#[test]
fn cbc_works1() {
	let plaintext: Vec<u64> = vec![0x7469206564616d20, 0x6c61766975716520];
	let key: [u64; 2] = [0x0706050403020100, 0x0f0e0d0c0b0a0908];
	let iv1: [u64; 2] = [0xAFF92B19D2240A90, 0xDD55C781B2E48BB0];

	let s: Speck = Speck::new(&key);

	let ciphertext1:    Vec<u64> = s.cbc_encrypt_blocks(&iv1, &plaintext);
	let decryptedtext1: Vec<u64> = s.cbc_decrypt_blocks(&iv1, &ciphertext1);
	assert_eq!(decryptedtext1, plaintext);
}

#[test]
fn cbc_works2() {
	let long_plaintext: Vec<u64> = vec![0xB6ECC96CEC3EE647, 0x0D698FDCED742594, 0x78BCB34D52D1B961, 0xA03EF56F828A60DE, 0xE725480B83C30B2C, 0xE57669757165C2BA];
	let key: [u64; 2] = [0x0706050403020100, 0x0f0e0d0c0b0a0908];
	let iv2: [u64; 2] = [0xD2C4B7D96C49160E, 0x4EFE0C3E3B9FFD85];

	let s: Speck = Speck::new(&key);

	let ciphertext2:    Vec<u64> = s.cbc_encrypt_blocks(&iv2, &long_plaintext);
	let decryptedtext2: Vec<u64> = s.cbc_decrypt_blocks(&iv2, &ciphertext2);
	assert_eq!(decryptedtext2, long_plaintext);
}
