//TODO:
//struct PKCS5;

pub enum PaddingError {WrongPadding, WrongCiphertextLength, WrongBlockLength}

pub trait PaddingGenerator {
	fn set_padding (&self, plaintext: &[u8], block_len: usize) -> Result<Vec<u8>, PaddingError>;
	fn remove_padding<'life> (&'life self, ciphertext: &'life[u8], block_len: usize) -> Result<&[u8], PaddingError>;
}