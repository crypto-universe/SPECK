//   128/128

const ALPHA:   u8 = 8;
const BETA:    u8 = 3;
pub const KEY_LEN: usize = 2;
pub const ROUNDS:  usize = 32;

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

	pub fn speck_encrypt(&self, plaintext: &[u64; 2]) -> [u64; 2]{
		let mut ciphertext: [u64; 2] = [plaintext[1], plaintext[0]];

		for i in 0..ROUNDS {
			speck_round_forward(&mut ciphertext, self.keys_propagated[i]);
		}
	
		[ciphertext[1], ciphertext[0]]
	}

	pub fn speck_decrypt(&self, ciphertext: &[u64; 2]) -> [u64; 2]{
		let mut decrypted: [u64; 2] = [ciphertext[1], ciphertext[0]];

		for i in (0..ROUNDS).rev() {
			speck_round_backward(&mut decrypted, self.keys_propagated[i]);
		}
	
		[decrypted[1], decrypted[0]]
	}
}

#[inline(always)]
fn speck_round_forward(x: &mut [u64; 2], key: u64) {
	x[0] = ((ror(x[0], ALPHA)).wrapping_add(x[1])) ^ key;
	x[1] = rol(x[1], BETA) ^ (x[0]);
}

#[inline(always)]
fn speck_round_backward(x: &mut [u64; 2], key: u64) {
	x[1] = ror((x[1] ^ x[0]), BETA);
	x[0] = rol(((x[0] ^ key).wrapping_sub(x[1])), ALPHA);
}

#[inline(always)]
fn rol(num: u64, amount: u8) -> u64 {
	(num << amount) | (num >> (64-amount))
}

#[inline(always)]
fn ror(num: u64, amount: u8) -> u64 {
	(num >> amount) | (num << (64-amount))
}

#[test]
fn it_works1() {
	let plain_text: [u64; 2] = [0x7469206564616d20, 0x6c61766975716520];
	let key: [u64; 2] = [0x0706050403020100, 0x0f0e0d0c0b0a0908];

	let s: Speck = Speck::new(&key);
	
	let ciphertext: [u64; 2] = s.speck_encrypt(&plain_text);
	assert_eq!(ciphertext[0], 0x7860fedf5c570d18);
	assert_eq!(ciphertext[1], 0xa65d985179783265);

	let decryptedtext: [u64; 2] = s.speck_decrypt(&ciphertext);
	assert_eq!(decryptedtext[0], plain_text[0]);
	assert_eq!(decryptedtext[1], plain_text[1]);
}
