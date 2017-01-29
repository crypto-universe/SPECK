use speck::Speck;
use padding::*;
use block128::*;
use std::marker::PhantomData;
use std::iter::{ExactSizeIterator, Iterator};

pub const BYTES_IN_BLOCK: usize = 16;

pub struct CBC <PG> {
	padd_generator: PhantomData<PG>,
}

pub struct CBCEncryptIter<IB> {
	block_cipher: Speck,
	plaintext: IB,
	prev: Block128
}

pub struct CBCDecryptIter<JB> {
	block_cipher: Speck,
	ciphertext: JB,
	prev: Block128
}

impl<IB> Iterator for CBCEncryptIter<IB> where IB: ExactSizeIterator<Item=Block128> {
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

impl<IB> ExactSizeIterator for CBCEncryptIter<IB> where IB: ExactSizeIterator<Item=Block128> {
	fn len(&self) -> usize {
		self.plaintext.len()
	}
}

impl<JB> Iterator for CBCDecryptIter<JB> where JB: ExactSizeIterator<Item=Block128>{
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

impl<JB> ExactSizeIterator for CBCDecryptIter<JB> where JB: ExactSizeIterator<Item=Block128> {
	fn len(&self) -> usize {
		self.ciphertext.len()
	}
}

impl <PG: PaddingGenerator> CBC <PG> {
	pub fn new() -> CBC<PG> {
		CBC {padd_generator: PhantomData::<PG> }
	}

	pub fn encrypt_blocks<IB>(&self, iv: Block128, key: Block128, plaintext: IB) -> CBCEncryptIter<IB> where IB: Iterator<Item=Block128> {
		CBCEncryptIter{block_cipher: Speck::new(&key), plaintext: plaintext, prev: iv}
	}

	pub fn decrypt_blocks<JB>(&self, iv: Block128, key: Block128, ciphertext: JB) -> CBCDecryptIter<JB> where JB: Iterator<Item=Block128> {
		CBCDecryptIter{block_cipher: Speck::new(&key), ciphertext: ciphertext, prev: iv}
	}

//Byte128Iter<CBCEncryptIter<Block128Iter<MyChain<KB, <PG as PaddingGenerator>::PaddingIterator>>>>
	pub fn encrypt_bytes<KB>(&self, iv: Block128, key: Block128, plaintext: KB) -> impl Iterator<Item=u8> where KB: ExactSizeIterator<Item=u8>,
	{
		let padded_plaintext = PG::set_padding(plaintext, BYTES_IN_BLOCK);
		let block_iter = Block128::to_block_iter(padded_plaintext);
		let enc_blocks: CBCEncryptIter<Block128Iter<MyChain<KB, <PG as PaddingGenerator>::PaddingIterator>>> = self.encrypt_blocks(iv, key, block_iter);
		let enc_bytes = Block128::to_byte_iter(enc_blocks);

		enc_bytes
	}

	pub fn decrypt_bytes<LB>(&self, iv: Block128, key: Block128, ciphertext: LB) -> Result<(impl Iterator<Item=u8> + ExactSizeIterator<Item=u8>), String> 
	where LB: ExactSizeIterator<Item=u8> {
		let encrypted_blocks = Block128::to_block_iter(ciphertext);
		let decrypted_blocks = self.decrypt_blocks(iv, key, encrypted_blocks);
		let decrypted_bytes = Block128::to_byte_iter(decrypted_blocks);
		match (PG::remove_padding(decrypted_bytes, BYTES_IN_BLOCK)) {
			Ok(result) => Ok(result),
			Err(e) => Err("Decryption failed.".to_owned()),		//No leak of error details info
		}
	}
}


#[test]
fn cbc_works1() {
	use pkcs7::PKCS7;
	let plaintext1 = [0x74, 0x69, 0x20, 0x65, 0x64, 0x61, 0x6d, 0x20, 0x6c, 0x61, 0x76, 0x69, 0x75, 0x71, 0x65, 0x20];
	let plaintext2 = Block128::new(0x7469206564616d20, 0x6c61766975716520);
	let key = Block128::new(0x0706050403020100, 0x0f0e0d0c0b0a0908);
	let iv1 = Block128::new(0xAFF92B19D2240A90, 0xDD55C781B2E48BB0);

	let c: CBC<PKCS7> = CBC::new();
	let s: Speck = Speck::new(&key);

	let mut ciphertext1 = c.encrypt_bytes(iv1, key, plaintext1.iter());
	let mut ciphertext2 = c.encrypt_blocks(iv1, key, ::std::iter::once(plaintext2)).next().unwrap().iter();
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
