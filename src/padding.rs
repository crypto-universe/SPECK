//TODO:
//struct PKCS5;

#[derive(Debug)]	//For "unwrap" in tests
pub enum PaddingError {WrongPadding, WrongCiphertextLength, WrongBlockLength}

pub trait PaddingGenerator {
	fn set_padding (plaintext: &[u8], padding: &mut[u8], block_len: usize);
	fn remove_padding (ciphertext: &[u8], block_len: usize) -> Result<usize, PaddingError>;
}
