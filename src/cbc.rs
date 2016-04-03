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

pub struct CBCEncryptIter<'a, 'b> {
	block_cipher: &'a Speck,
	//TODO: Consider Iterator<u64> to handle padding easier
	plaintext: &'b [u64],
	i: usize,
	prev_1: u64,
	prev_2: u64,
}

pub struct CBCDecryptIter<'c, 'd> {
	block_cipher: &'c Speck,
	ciphertext: &'d [u64],
	i: usize,
	temp: u64,
	prev_1: u64,
	prev_2: u64,
}

impl<'a, 'b> Iterator for CBCEncryptIter<'a, 'b> {
	type Item = u64;

	fn next(&mut self) -> Option<u64> {
		//Simple situation - no padding.

		if (self.i % 2 == 1) {
			self.i += 1;
			return Some(self.prev_2);
		}
		
		if (self.i < self.plaintext.len()) {
			let (a, b) = self.block_cipher.speck_encrypt(self.plaintext[self.i] ^ self.prev_1, self.plaintext[self.i+1] ^ self.prev_2);
			self.prev_1 = a;
			self.prev_2 = b;
			self.i += 1;
			return Some(a);
		}
		else {
			//If plaintext.is_empty() or end of plaintext
			return None;
		}
	}
}

impl<'c, 'd> Iterator for CBCDecryptIter<'c, 'd> {
	type Item = u64;

	fn next(&mut self) -> Option<u64> {
		//TODO: Remove padding
		
		if (self.i % 2 == 1) {
			self.i += 1;
			return Some(self.temp);
		}
		
		if (self.i < self.ciphertext.len()) {
			let (a, b) = self.block_cipher.speck_decrypt(self.ciphertext[self.i], self.ciphertext[self.i+1]);
			self.temp = b ^ self.prev_2;
			let result = a ^ self.prev_1;
			self.prev_1 = self.ciphertext[self.i];
			self.prev_2 = self.ciphertext[self.i+1];
			self.i += 1;
			return Some(result);
		}
		else {
			return None;
		}
	}
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

	pub fn encrypt_blocks<'a>(&'a self, plaintext: &'a [u64]) -> CBCEncryptIter {
		assert!(plaintext.len() % WORDS_IN_BLOCK == 0, "Input buffer has odd length {0}!", plaintext.len());
		
		//TODO: Remove assert and generate padding here
		CBCEncryptIter{block_cipher: &self.block_cipher, plaintext: plaintext, i: 0, prev_1: self.iv[0], prev_2: self.iv[1]}
	}

	pub fn decrypt_blocks<'c>(&'c self, ciphertext: &'c [u64]) -> CBCDecryptIter {
		assert!(ciphertext.len() % WORDS_IN_BLOCK == 0, "Input buffer has odd length {0}!", ciphertext.len());
		
		//TODO: Remove assert as soon as introduce Block instead of u64
		CBCDecryptIter{block_cipher: &self.block_cipher, ciphertext: ciphertext, i: 0, temp: 0, prev_1: self.iv[0], prev_2: self.iv[1]}
	}

	//#[deprecated]
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

	//#[deprecated]
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

		//TODO: Do not collect padded text. Use it in lazy way, as Iterator
		let padded_plaintext: Vec<u8> = self.padd_generator.set_padding(plaintext.iter().cloned(), BYTES_IN_BLOCK).collect::<Vec<u8>>();
		let padded_plaintext_u64:  &[u64] = util::bytes_to_words(padded_plaintext.as_slice()/*, BYTES_IN_WORD*/);

		let mut ciphertext: Vec<u8> = Vec::with_capacity(padded_plaintext.len());

		let (mut a, mut b) = self.block_cipher.speck_encrypt(padded_plaintext_u64[0].to_be() ^ self.iv[0], padded_plaintext_u64[1].to_be() ^ self.iv[1]);
		ciphertext.extend_from_slice(util::words_to_bytes(&[a, b]));

//		TODO: Better way, but non-working right now
//		for i in (2..plaintext.len()).step_by(2) {
		for i in (2 .. padded_plaintext_u64.len()).filter(|x| x % 2 == 0) {
			let (c, d) = self.block_cipher.speck_encrypt(padded_plaintext_u64[i].to_be() ^ a, padded_plaintext_u64[i+1].to_be() ^ b);
			ciphertext.extend_from_slice(util::words_to_bytes(&[c, d]));
			a = c;
			b = d;
		}

		Ok(ciphertext)
	}

	pub fn cbc_decrypt_byte_array(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CipherErrors> {
		if (ciphertext.is_empty() || ciphertext.len() % BYTES_IN_BLOCK != 0) { return Err(CipherErrors::WrongInput) };

		let ciphertext_u64: &[u64] = util::bytes_to_words(&ciphertext/*, BYTES_IN_WORD*/);

		let mut decrypted: Vec<u8> = Vec::with_capacity(ciphertext.len());

		let (mut a, mut b) = self.block_cipher.speck_decrypt(ciphertext_u64[0].to_be(), ciphertext_u64[1].to_be());
		decrypted.extend_from_slice(util::words_to_bytes(&[a^self.iv[0], b^self.iv[1]]));

		for i in (2 .. ciphertext_u64.len()).filter(|x| x % 2 == 0) {
			let (c, d) = self.block_cipher.speck_decrypt(ciphertext_u64[i].to_be(), ciphertext_u64[i+1].to_be() ^ b);
			decrypted.extend_from_slice(util::words_to_bytes(&[c^a, d^b]));
			a = c;
			b = d;
		}

		/*match self.padd_generator::remove_padding(&decrypted, BYTES_IN_BLOCK) {
			Err(_)        => Err(CipherErrors::WrongPadding),
			Ok(plaintext_len) => {
				while (decrypted.len() > plaintext_len) {
					decrypted.pop();
				}
				Ok(decrypted)
			},
		}*/
		Err(CipherErrors::WrongPadding)
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

	let ciphertext3:    Vec<u64> = c.encrypt_blocks(&long_plaintext).collect();
	let decryptedtext3: Vec<u64> = c.decrypt_blocks(&ciphertext2).collect();
	assert_eq!(ciphertext2, ciphertext3);
	assert_eq!(decryptedtext2, decryptedtext3);
}
