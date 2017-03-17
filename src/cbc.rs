#![allow(unused_parens)]

use block128;
use block128::Block128;
use speck_128_128::Speck_128_128;
use padding::PaddingGenerator;
use pkcs7::PKCS7;
use util;
use std::marker::PhantomData;

pub const BYTES_IN_WORD: usize = 8;
pub const WORDS_IN_BLOCK: usize = 2;

pub enum CipherErrors {WrongPadding, WrongInput}

pub struct CBC <PG> {
	iv: Block128,
	block_cipher: Speck_128_128,
	padd_generator: PhantomData<PG>,
}

impl <PG: PaddingGenerator> CBC <PG> {
	pub fn new<U: Into<Block128>>(iv: U, key: U) -> CBC<PG> {
		CBC {iv: iv.into(), block_cipher: Speck_128_128::new(key.into()), padd_generator: PhantomData::<PG> }
	}

	pub fn cbc_encrypt_blocks(&self, plaintext: &[u64]) -> Vec<u64> {
		assert!(!plaintext.is_empty(), "Input plaintext should not be empty!");
		assert!(plaintext.len() % WORDS_IN_BLOCK == 0, "Input buffer has odd length {0}!", plaintext.len());

		let mut ciphertext: Vec<u64> = Vec::with_capacity(plaintext.len()/BYTES_IN_WORD+2);

		let (a, b) = self.block_cipher.speck_encrypt(plaintext[0] ^ self.iv.get_a(), plaintext[1] ^ self.iv.get_b());
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
		decryptedtext.push(a ^ self.iv.get_a());
		decryptedtext.push(b ^ self.iv.get_b());

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

		let mut last_block: [u8; block128::BYTES_IN_BLOCK] = [0; block128::BYTES_IN_BLOCK];
		PG::set_padding(plaintext, &mut last_block, block128::BYTES_IN_BLOCK);

		let last_block_u64: &[u64] = util::bytes_to_words(&last_block);
		let plaintext_u64:  &[u64] = util::bytes_to_words(plaintext/*, BYTES_IN_WORD*/);

		let mut ciphertext: Vec<u8> = Vec::with_capacity(plaintext.len() + last_block.len());

		let (mut a, mut b) = self.block_cipher.speck_encrypt(
			plaintext_u64[0].to_be() ^ self.iv.get_a(), plaintext_u64[1].to_be() ^ self.iv.get_b());
		ciphertext.extend_from_slice(util::words_to_bytes(&[a, b]));

//		TODO: Better way, but non-working right now
//		for i in (2..plaintext.len()).step_by(2) {
		for i in (2 .. plaintext_u64.len()).filter(|x| x % 2 == 0) {
			let (c, d) = self.block_cipher.speck_encrypt(plaintext_u64[i].to_be() ^ a, plaintext_u64[i+1].to_be() ^ b);
			ciphertext.extend_from_slice(util::words_to_bytes(&[c, d]));
			a = c;
			b = d;
		}
		let (c, d) = self.block_cipher.speck_encrypt(last_block_u64[0].to_be() ^ a, last_block_u64[1].to_be() ^ b);
		ciphertext.extend_from_slice(util::words_to_bytes(&[c, d]));

		Ok(ciphertext)
	}

	pub fn cbc_decrypt_byte_array(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CipherErrors> {
		if (ciphertext.is_empty() || ciphertext.len() % block128::BYTES_IN_BLOCK != 0) { return Err(CipherErrors::WrongInput) };

		let ciphertext_u64: &[u64] = util::bytes_to_words(&ciphertext/*, BYTES_IN_WORD*/);

		let mut decrypted: Vec<u8> = Vec::with_capacity(ciphertext.len());

		let (mut a, mut b) = self.block_cipher.speck_decrypt(ciphertext_u64[0].to_be(), ciphertext_u64[1].to_be());
		decrypted.extend_from_slice(util::words_to_bytes(&[a^self.iv.get_a(), b^self.iv.get_b()]));

		for i in (2 .. ciphertext_u64.len()).filter(|x| x % 2 == 0) {
			let (c, d) = self.block_cipher.speck_decrypt(ciphertext_u64[i].to_be(), ciphertext_u64[i+1].to_be() ^ b);
			decrypted.extend_from_slice(util::words_to_bytes(&[c^a, d^b]));
			a = c;
			b = d;
		}

		match PG::remove_padding(&decrypted, block128::BYTES_IN_BLOCK) {
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
	let key: Block128 = Block128::from(0x07060504030201000f0e0d0c0b0a0908);
	let iv1: Block128 = Block128::from(0xAFF92B19D2240A90DD55C781B2E48BB0);

	let s: Speck_128_128 = Speck_128_128::new(key.clone());
	let c: CBC<PKCS7> = CBC::new(iv1.clone(), key.clone());

	let ciphertext1: Vec<u64> = c.cbc_encrypt_blocks(&plaintext);
	let (ct1, ct2) = s.speck_encrypt(iv1.get_a() ^ plaintext[0], iv1.get_b() ^ plaintext[1]);
	assert_eq!(ciphertext1, [ct1, ct2].to_vec());

	let decryptedtext1: Vec<u64> = c.cbc_decrypt_blocks(&ciphertext1);
	assert_eq!(decryptedtext1, plaintext);
}

#[test]
fn cbc_works2() {
	let long_plaintext = [0xB6ECC96CEC3EE647, 0x0D698FDCED742594, 0x78BCB34D52D1B961, 0xA03EF56F828A60DE, 0xE725480B83C30B2C, 0xE57669757165C2BA];
	let key: [u64; 2]  = [0x0706050403020100, 0x0f0e0d0c0b0a0908];
	let iv2: [u64; 2]  = [0xD2C4B7D96C49160E, 0x4EFE0C3E3B9FFD85];

	let c: CBC<PKCS7> = CBC::new(&iv2, &key);

	let ciphertext2:    Vec<u64> = c.cbc_encrypt_blocks(&long_plaintext);
	let decryptedtext2: Vec<u64> = c.cbc_decrypt_blocks(&ciphertext2);
	assert_eq!(decryptedtext2, long_plaintext);
}
