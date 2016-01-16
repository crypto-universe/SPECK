#![allow(unused_parens)]

use speck::Speck;
use padding::PaddingGenerator;
use pkcs7::PKCS7;
use util;

pub const BYTES_IN_WORD: usize = 8;
pub const WORDS_IN_BLOCK: usize = 2;
pub const BYTES_IN_BLOCK: usize = 16;

pub enum CipherErrors {WrongPadding, WrongInput}

pub struct CBC {
	iv: [u64; 2],
	block_cipher: Speck,
	padd_generator: PKCS7,
}

impl CBC {
	pub fn new_w(iv: &[u64; WORDS_IN_BLOCK], key: &[u64; WORDS_IN_BLOCK]) -> CBC {
		CBC {iv: iv.clone(), block_cipher: Speck::new(key), padd_generator: PKCS7 }
	}
	
	pub fn new_b(iv: &[u8; BYTES_IN_BLOCK], key: &[u8; BYTES_IN_BLOCK]) -> CBC {
		let iv2  = util::bytes_to_words(iv);
		let key2 = util::bytes_to_words(key);
		let iv3  = [iv2[0].to_be(), iv2[1].to_be()];
		let key3 = [key2[0].to_be(), key2[1].to_be()];
		CBC {iv: iv3, block_cipher: Speck::new(&key3), padd_generator: PKCS7 }
	}
	
	pub fn cbc_encrypt_blocks(&self, plaintext: &[u64]) -> Vec<u64> {
		assert!(!plaintext.is_empty(), "Input plaintext should not be empty!");
		assert!(plaintext.len() % WORDS_IN_BLOCK == 0, "Input buffer has odd length {0}!", plaintext.len());

		let mut ciphertext: Vec<u64> = Vec::with_capacity(plaintext.len()/BYTES_IN_WORD+2);

		let (a, b) = self.block_cipher.speck_encrypt(plaintext[0] ^ self.iv[0], plaintext[1] ^ self.iv[1]);
		ciphertext.push(a);
		ciphertext.push(b);

//		TODO: Better way, but non-working right now
//		for i in (2..plaintext.len()).step_by(2) {
		for i in (2 .. plaintext.len()).filter(|x| x % 2 == 0) {
			let (c, d) = self.block_cipher.speck_encrypt(plaintext[i] ^ ciphertext[i-2], plaintext[i+1] ^ ciphertext[i-1]);
			ciphertext.push(c);
			ciphertext.push(d);
		}

		ciphertext
	}

	pub fn cbc_decrypt_blocks(&self, ciphertext: &[u64]) -> Vec<u64> {
		assert!(!ciphertext.is_empty(), "Input ciphertext should not be empty!");
		assert!(ciphertext.len() % WORDS_IN_BLOCK == 0, "Input buffer has odd length {0}!", ciphertext.len());

		let mut decryptedtext: Vec<u64> = Vec::with_capacity(ciphertext.len()/BYTES_IN_WORD+2);

		let (a, b) = self.block_cipher.speck_decrypt(ciphertext[0], ciphertext[1]);
		decryptedtext.push(a ^ self.iv[0]);
		decryptedtext.push(b ^ self.iv[1]);

//		TODO: Use step_by in future
		for i in (2 .. ciphertext.len()).filter(|x| x % 2 == 0) {
			let (c, d) = self.block_cipher.speck_decrypt(ciphertext[i], ciphertext[i+1]);
			decryptedtext.push(c ^ ciphertext[i-2]);
			decryptedtext.push(d ^ ciphertext[i-1]);
		}

		decryptedtext
	}

	pub fn cbc_encrypt_byte_array(&self, plaintext: &[u8]) -> Result<Vec<u8>, CipherErrors> {
		if (plaintext.is_empty()) { return Err(CipherErrors::WrongInput) };

		let mut last_block: [u8; BYTES_IN_BLOCK] = [0; BYTES_IN_BLOCK];
		self.padd_generator.set_padding(plaintext, &mut last_block, BYTES_IN_BLOCK);

		let last_block_u64: &[u64] = util::bytes_to_words(&last_block);
		let plaintext_u64:  &[u64] = util::bytes_to_words(plaintext/*, BYTES_IN_WORD*/);

		let mut ciphertext: Vec<u8> = Vec::with_capacity(plaintext.len() + last_block.len());

		let (mut a, mut b) = self.block_cipher.speck_encrypt(plaintext_u64[0].to_be() ^ self.iv[0], plaintext_u64[1].to_be() ^ self.iv[1]);
		//TODO: remove it!
		util::my_extend_from_slice(&mut ciphertext, util::words_to_bytes(&[a, b]));

//		TODO: Better way, but non-working right now
//		for i in (2..plaintext.len()).step_by(2) {
		for i in (2 .. plaintext_u64.len()).filter(|x| x % 2 == 0) {
			let (c, d) = self.block_cipher.speck_encrypt(plaintext_u64[i].to_be() ^ a, plaintext_u64[i+1].to_be() ^ b);
			//TODO: remove it!
			util::my_extend_from_slice(&mut ciphertext, util::words_to_bytes(&[c, d]));
			a = c;
			b = d;
		}
		let (c, d) = self.block_cipher.speck_encrypt(last_block_u64[0].to_be() ^ a, last_block_u64[1].to_be() ^ b);
		//TODO: remove it!
		util::my_extend_from_slice(&mut ciphertext, util::words_to_bytes(&[c, d]));

		Ok(ciphertext)
	}

	pub fn cbc_decrypt_byte_array(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CipherErrors> {
		if (ciphertext.is_empty() || ciphertext.len() % BYTES_IN_BLOCK != 0) { return Err(CipherErrors::WrongInput) };

		let ciphertext_u64: &[u64] = util::bytes_to_words(&ciphertext/*, BYTES_IN_WORD*/);

		let mut decrypted: Vec<u8> = Vec::with_capacity(ciphertext.len());

		let (mut a, mut b) = self.block_cipher.speck_decrypt(ciphertext_u64[0].to_be(), ciphertext_u64[1].to_be());
		//TODO: replace by standard func
		util::my_extend_from_slice(&mut decrypted, util::words_to_bytes(&[a^self.iv[0], b^self.iv[1]]));

		for i in (2 .. ciphertext_u64.len()).filter(|x| x % 2 == 0) {
			let (c, d) = self.block_cipher.speck_decrypt(ciphertext_u64[i].to_be(), ciphertext_u64[i+1].to_be() ^ b);
			//TODO: remove it!
			util::my_extend_from_slice(&mut decrypted, util::words_to_bytes(&[c^a, d^b]));
			a = c;
			b = d;
		}

		match self.padd_generator.remove_padding(&decrypted, BYTES_IN_BLOCK) {
			Err(_)        => Err(CipherErrors::WrongPadding),
			Ok(plaintext_len) => {
				while (decrypted.len() > plaintext_len) {
					decrypted.pop();
				}
				Ok(decrypted)
			},
		}
	}
}




#[test]
fn cbc_works1() {
	let plaintext     = [0x7469206564616d20, 0x6c61766975716520];
	let key: [u64; 2] = [0x0706050403020100, 0x0f0e0d0c0b0a0908];
	let iv1: [u64; 2] = [0xAFF92B19D2240A90, 0xDD55C781B2E48BB0];

	let s: Speck = Speck::new(&key);
	let c: CBC = CBC::new_w(&iv1, &key);

	let ciphertext1: Vec<u64> = c.cbc_encrypt_blocks(&plaintext);
	let (ct1, ct2) = s.speck_encrypt(iv1[0] ^ plaintext[0], iv1[1] ^ plaintext[1]);
	assert_eq!(ciphertext1, [ct1, ct2].to_vec());

	let decryptedtext1: Vec<u64> = c.cbc_decrypt_blocks(&ciphertext1);
	assert_eq!(decryptedtext1, plaintext);
}

#[test]
fn cbc_works2() {
	let long_plaintext = [0xB6ECC96CEC3EE647, 0x0D698FDCED742594, 0x78BCB34D52D1B961, 0xA03EF56F828A60DE, 0xE725480B83C30B2C, 0xE57669757165C2BA];
	let key: [u64; 2]  = [0x0706050403020100, 0x0f0e0d0c0b0a0908];
	let iv2: [u64; 2]  = [0xD2C4B7D96C49160E, 0x4EFE0C3E3B9FFD85];

	let c: CBC = CBC::new_w(&iv2, &key);

	let ciphertext2:    Vec<u64> = c.cbc_encrypt_blocks(&long_plaintext);
	let decryptedtext2: Vec<u64> = c.cbc_decrypt_blocks(&ciphertext2);
	assert_eq!(decryptedtext2, long_plaintext);
}
