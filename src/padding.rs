#![allow(unused_parens)]

pub enum PaddingError {WrongPadding, WrongCiphertextLength/*, WrongBlockLength*/}

pub trait PaddingGenerator {
	type PaddingIterator: Iterator<Item=u8>;

	fn set_padding<I: ExactSizeIterator<Item=u8>>(&self, plaintext: I, block_len: usize) -> ::std::iter::Chain<I, Self::PaddingIterator>;
	fn remove_padding (&self, ciphertext: &[u8], block_len: usize) -> Result<usize, PaddingError>;
}
