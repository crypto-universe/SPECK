#![allow(unused_parens)]
//TODO:
//struct PKCS5;

extern crate num;
use self::num::NumCast;

pub enum PaddingError {WrongPadding, WrongCiphertextLength, WrongBlockLength}

pub trait PaddingGenerator<T: NumCast + Copy> {
	fn set_padding<'a>(plaintext: &'a [T], block_len: usize) -> SetPaddingIterator<T>;
	fn remove_padding (ciphertext: &[T], block_len: usize) -> Result<usize, PaddingError>;
}

pub struct SetPaddingIterator<'v, T: 'v + NumCast + Copy> {
	input: &'v [T],
	index: usize,
	padding: usize,
}

impl<'v, T: NumCast + Copy> SetPaddingIterator<'v, T> {
	pub fn new(plaintext: &'v [T], padding_size: usize) -> SetPaddingIterator<T> {
		SetPaddingIterator{input: plaintext, index: 0, padding: padding_size}
	}
}

impl<'v, T: NumCast + Copy> Iterator for SetPaddingIterator<'v, T> {
	type Item = T;

	fn next(&mut self) -> Option<T> {
		self.index += 1;
		return match (self.index-1){
			i if (i < self.input.len()) => return Some(self.input[i].clone()),
			i if (i >= self.input.len() && i < self.input.len()+self.padding) => {
				match (self::num::cast(self.padding)) {
					Some(x) => Some(x),
					None    => panic!("Non convertable type T in padding!"),
				}
			},
			_ => None,
		}
	}
}
