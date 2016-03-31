#![allow(unused_parens)]

pub enum PaddingError {WrongPadding, WrongCiphertextLength, WrongBlockLength}

pub trait PaddingGenerator {
	fn set_padding<'a>(plaintext: &'a [u8], block_len: usize) -> SetPaddingIterator<'a>;
	fn remove_padding (ciphertext: &[u8], block_len: usize) -> Result<usize, PaddingError>;
}

pub struct SetPaddingIterator<'v> {
	input: &'v [u8],
	index: usize,
	padding: usize,
}

impl <'v> SetPaddingIterator<'v> {
	pub fn new(plaintext: &'v [u8], padding_size: usize) -> SetPaddingIterator<'v> {
		SetPaddingIterator{input: plaintext, index: 0, padding: padding_size}
	}
}

impl <'v> Iterator for SetPaddingIterator<'v> {
	type Item = u8;

	fn next(&mut self) -> Option<u8> {
		self.index += 1;
		return match (self.index-1){
			i if (i < self.input.len()) => return Some(self.input[i].clone()),
			i if (i >= self.input.len() && i < self.input.len()+self.padding) => Some(self.padding as u8),
			_ => None,
		}
	}
}
