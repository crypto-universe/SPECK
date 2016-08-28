#[derive(Debug)]
//ALARM! Prevent this info to leak! Otherwise system will be vulnerable to padding oracle attack!
pub enum PaddingError {WrongPadding, WrongCiphertextLength/*, WrongBlockLength*/}

pub trait PaddingGenerator {
	type PaddingIterator: Iterator<Item=u8>;

	fn set_padding<I: ExactSizeIterator<Item=u8>> (plaintext: I, block_len: usize) -> MyChain<I, Self::PaddingIterator>;
	fn remove_padding<J: ExactSizeIterator<Item=u8> + DoubleEndedIterator<Item=u8>> (ciphertext: J, block_len: usize) -> Result<J, PaddingError>;
}

//============== Special return type, which implements ExactSizeIterator ==================

pub struct MyChain<A, B> {
	chain: ::std::iter::Chain<A, B>,
	length: usize,	//Be careful, length overflow possible (in theory)!
}

impl<A, B> MyChain<A, B> where
	A: ExactSizeIterator<Item=u8>,
	B: Iterator<Item=A::Item>
{
	pub fn new(iter1: A, iter2: B, iter2_len: usize) -> MyChain<A, B>{
		let local_len = iter1.len() + iter2_len;
		MyChain {chain: iter1.chain(iter2), length: local_len}
	}
}

impl<A, B> Iterator for MyChain<A, B> where
	A: ExactSizeIterator<Item=u8>,
	B: Iterator<Item=A::Item>
{
	type Item = u8;

	fn next(&mut self) -> Option<Self::Item> {
		self.chain.next()
	}
}

impl<A, B> ExactSizeIterator for MyChain<A, B> where
	A: ExactSizeIterator<Item=u8>,
	B: Iterator<Item=A::Item>
{
	fn len(&self) -> usize {
		self.length
	}
}

//============== Functions for testing paddings ==================

pub type PaddingTuple<'a> = (&'a [u8], usize, &'a [u8]);

pub fn _check_set_padding<T: PaddingGenerator>(pt: PaddingTuple) {
	let (raw_text, b, padded_text) = pt;
	let padded_vec: Vec<u8> = T::set_padding(raw_text.iter().cloned(), b).collect::<Vec<u8>>();
	assert_eq!(padded_vec.as_slice(), padded_text);
}

pub fn _check_remove_padding<T: PaddingGenerator>(pt: PaddingTuple) {
	let (raw_text, b, padded_text) = pt;
	let new_raw_text = T::remove_padding(padded_text.iter().cloned(), b);
	match (new_raw_text) {
		Ok(some_iter) => assert_eq!(some_iter.collect::<Vec<u8>>().as_slice(), raw_text),
		Err(some_err) => panic!("Padding error!\n Input:    {:?}\n Expected: {:?}\n Block length: {:?}\n Error type: {:?}\n", padded_text, raw_text, b, some_err),
	}
}

pub fn _check_padding<T: PaddingGenerator>(pt: PaddingTuple) {
	_check_set_padding::<T>(pt);
	_check_remove_padding::<T>(pt);
}
