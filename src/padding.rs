//TODO:
//struct PKCS5;

#[derive(Debug)]	//For "unwrap" in tests
pub enum PaddingError {WrongPadding, WrongCiphertextLength, WrongBlockLength}

pub trait PaddingGenerator<T> {
	fn set_padding (&self, plaintext: &[T], padding: &mut[T], block_len: usize);
	fn remove_padding (&self, ciphertext: &[T], block_len: usize) -> Result<usize, PaddingError>;
}
