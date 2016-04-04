#![allow(unused_parens)]

#[derive(Debug)]
//ALARM! Prevent this info to leak! Otherwise system will be vulnerable to padding oracle attack!
pub enum PaddingError {WrongPadding, WrongCiphertextLength/*, WrongBlockLength*/}

pub trait PaddingGenerator {
	type PaddingIterator: Iterator<Item=u8>;

	fn set_padding<I: ExactSizeIterator<Item=u8>> (&self, plaintext: I, block_len: usize) -> ::std::iter::Chain<I, Self::PaddingIterator>;
	fn remove_padding<J: ExactSizeIterator<Item=u8> + DoubleEndedIterator<Item=u8>> (&self, ciphertext: J, block_len: usize) -> Result<J, PaddingError>;
}
