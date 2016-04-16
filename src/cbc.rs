#![allow(unused_parens)]

use speck::Speck;
use padding::*;
use block128::*;
use std::marker::PhantomData;
use std::iter::{ExactSizeIterator, FromIterator, Iterator};

pub const BYTES_IN_WORD: usize = 8;
pub const WORDS_IN_BLOCK: usize = 2;
pub const BYTES_IN_BLOCK: usize = 16;

pub enum CipherErrors {WrongPadding, WrongInput}

pub struct CBC <PG> {
	iv: Block128,
	block_cipher: Speck,
	padd_generator: PhantomData<PG>,
}

pub struct CBCEncryptIter<'a, IB> {
	block_cipher: &'a Speck,
	plaintext: IB,
	prev: Block128
}

pub struct CBCDecryptIter<'c, JB> {
	block_cipher: &'c Speck,
	ciphertext: JB,
	prev: Block128
}

impl<'a, IB> Iterator for CBCEncryptIter<'a, IB> where IB: ExactSizeIterator<Item=Block128> {
	type Item = Block128;

	fn next(&mut self) -> Option<Block128> {
		let current: Option<Block128> = self.plaintext.next();
		return match (current) {
			Some(block) => {
				let to_encrypt = block ^ self.prev;
				let encrypted = self.block_cipher.speck_encrypt(&to_encrypt);
				self.prev = encrypted;
				return Some(encrypted);
			},
			None => None,
		}
	}
}

impl<'a, IB> ExactSizeIterator for CBCEncryptIter<'a, IB> where IB: ExactSizeIterator<Item=Block128> {
	fn len(&self) -> usize {
		self.plaintext.len()
	}
}

impl<'c, JB> Iterator for CBCDecryptIter<'c, JB> where JB: Iterator<Item=Block128>{
	type Item = Block128;

	fn next(&mut self) -> Option<Block128> {
		let current: Option<Block128> = self.ciphertext.next();
		return match (current) {
			Some(block) => {
				let almost_decrypted = self.block_cipher.speck_decrypt(&block);
				let decrypted = almost_decrypted ^ self.prev;
				self.prev = block;
				return Some(decrypted);
			},
			None => None,
		}
	}
}

impl <PG: PaddingGenerator> CBC <PG> {
	pub fn new_w(iv: Block128, key: &Block128) -> CBC<PG> {
		CBC {iv: iv, block_cipher: Speck::new(key), padd_generator: PhantomData::<PG> }
	}

	pub fn new_b(iv: &[u8; BYTES_IN_BLOCK], key: &[u8; BYTES_IN_BLOCK]) -> CBC<PG> {
		CBC {iv: Block128::from_iter(iv.iter().cloned()), block_cipher: Speck::new(&Block128::from_iter(key.iter().cloned())), padd_generator: PhantomData::<PG> }
	}

	pub fn encrypt_blocks<'a, IB>(&'a self, plaintext: IB) -> CBCEncryptIter<IB> where IB: Iterator<Item=Block128> {
		CBCEncryptIter{block_cipher: &self.block_cipher, plaintext: plaintext, prev: self.iv}
	}

	pub fn decrypt_blocks<'c, JB>(&'c self, ciphertext: JB) -> CBCDecryptIter<JB> where JB: Iterator<Item=Block128> {
		CBCDecryptIter{block_cipher: &self.block_cipher, ciphertext: ciphertext, prev: self.iv}
	}

	pub fn encrypt_bytes<'b, KB>(&'b self, plaintext: KB) -> Byte128Iter<CBCEncryptIter<Block128Iter<MyChain<KB, <PG as PaddingGenerator>::PaddingIterator>>>> where
	KB: ExactSizeIterator<Item=u8>,
	{
		let padded_plaintext = PG::set_padding(plaintext, BYTES_IN_BLOCK);
		let block_iter = Block128::to_block_iter(padded_plaintext);
		let enc_blocks: CBCEncryptIter<Block128Iter<MyChain<KB, <PG as PaddingGenerator>::PaddingIterator>>> = self.encrypt_blocks(block_iter);
		let enc_bytes = Block128::to_byte_iter(enc_blocks);
		
		enc_bytes
	}
/*
	pub fn decrypt_bytes<'d, LB>(&'d self, ciphertext: LB) -> CBCDecryptIter<LB> where LB: Iterator<Item=u8> {
		let decrypted_blocks = CBCDecryptIter{block_cipher: &self.block_cipher, ciphertext: ciphertext, prev: self.iv}
	}
*/
}


#[test]
fn cbc_works1() {
	use pkcs7::PKCS7;
	let plaintext1 = [0x74, 0x69, 0x20, 0x65, 0x64, 0x61, 0x6d, 0x20, 0x6c, 0x61, 0x76, 0x69, 0x75, 0x71, 0x65, 0x20];
	let plaintext2 = Block128::new(0x7469206564616d20, 0x6c61766975716520);
	let key = Block128::new(0x0706050403020100, 0x0f0e0d0c0b0a0908);
	let iv1 = Block128::new(0xAFF92B19D2240A90, 0xDD55C781B2E48BB0);

	let c: CBC<PKCS7> = CBC::new_w(iv1, &key);
	let s: Speck = Speck::new(&key);

	let mut ciphertext1 = c.encrypt_bytes(plaintext1.into_iter().cloned());
	let mut ciphertext2 = c.encrypt_blocks(::std::iter::once(plaintext2)).next().unwrap().into_iter();
	let mut ciphertext3 = s.speck_encrypt(&(iv1 ^ plaintext2)).into_iter();

	for _ in 0..BYTES_IN_BLOCK {
		let x = ciphertext1.next().unwrap();
		let y = ciphertext2.next().unwrap();
		let z = ciphertext3.next().unwrap();
		assert_eq!(x, y);
		assert_eq!(y, z);
	}
}

/*
#[test]
fn cbc_works3() {
	use ansi_x923::ANSI_X923;

	let long_plaintext_src   = [0xB6, 0xEC, 0xC9, 0x6C, 0xEC, 0x3E, 0xE6, 0x47, 0x0D, 0x69, 0x8F, 0xDC, 0xED, 0x74, 0x25, 0x94,
								0x78, 0xBC, 0xB3, 0x4D, 0x52, 0xD1, 0xB9, 0x61, 0xA0, 0x3E, 0xF5, 0x6F, 0x82, 0x8A, 0x60, 0xDE,
								0xE7, 0x25, 0x48, 0x0B, 0x83, 0xC3, 0x0B, 0x2C, 0xE5, 0x76, 0x69, 0x75, 0x71, 0x65, 0xC2, 0xBA];
	let long_plaintext = long_plaintext_src
	let key: [u64; 2]  = [0x0706050403020100, 0x0f0e0d0c0b0a0908];
	let iv2: [u64; 2]  = [0xD2C4B7D96C49160E, 0x4EFE0C3E3B9FFD85];

	let c: CBC<ANSI_X923> = CBC::new_w(&iv2, &key);

	let ciphertext2:    Vec<u64> = c.cbc_encrypt_blocks(&long_plaintext);
	let decryptedtext2: Vec<u64> = c.cbc_decrypt_blocks(&ciphertext2);
	assert_eq!(decryptedtext2, long_plaintext);

	let ciphertext3:    Vec<u64> = c.encrypt_blocks(&long_plaintext).collect();
	let decryptedtext3: Vec<u64> = c.decrypt_blocks(&ciphertext2).collect();
	assert_eq!(ciphertext2, ciphertext3);
	assert_eq!(decryptedtext2, decryptedtext3);
}*/
