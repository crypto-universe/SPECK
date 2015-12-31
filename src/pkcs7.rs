#![allow(unused_parens)]

use padding::*;

pub struct PKCS7;

impl PaddingGenerator for PKCS7 {
	fn set_padding (&self, plaintext: &[u8], block_len: usize) -> Result<Vec<u8>, PaddingError> {
		if(block_len == 0 || block_len > 255) {
			return Err(PaddingError::WrongBlockLength);
		}

		let padding_size: usize = (block_len - plaintext.len()%block_len);

		let mut padded_text: Vec<u8> = plaintext.to_vec();

		match padding_size {
			//TODO: should be push_all
			0 => padded_text.append(&mut vec![block_len as u8; block_len]),
			_ => padded_text.append(&mut vec![padding_size as u8; padding_size]),
		}
		Ok(padded_text)
	}

	fn remove_padding<'life> (&'life self, ciphertext: &'life [u8], block_len: usize) -> Result<&[u8], PaddingError> {
		if (ciphertext.is_empty() || ciphertext.len() % block_len != 0) {
			return Err(PaddingError::WrongCiphertextLength);
		}

		let cl = ciphertext.len();
		let padding_size: u8 = ciphertext[cl - 1];

		let (text, padding) = ciphertext.split_at(cl - padding_size as usize);

		match padding.iter().all(|&x| x == padding_size) {
			true  => Ok(text),
			false => Err(PaddingError::WrongPadding),
		}
	}
}

#[test]
fn pkcs7_block_8() {
	let padd_gen = PKCS7;
	let wrong = [00];
	

	let text1: [u8; 0] = [];
	let expected1 =      [08; 08];
	let s_result1 = padd_gen.set_padding(&text1, 8).unwrap_or(Vec::new());
	assert_eq!(s_result1, expected1.to_vec());
	let r_result1 = padd_gen.remove_padding(&expected1, 8).unwrap_or(&wrong);
	assert_eq!(r_result1, text1);

	let text2: [u8; 5] = [0xAA, 0xCC, 0xEE, 0xBB, 0x13];
	let expected2 =      [0xAA, 0xCC, 0xEE, 0xBB, 0x13, 03, 03, 03];
	let s_result2 = padd_gen.set_padding(&text2, 8).unwrap_or(Vec::new());;
	assert_eq!(s_result2, expected2.to_vec());
	let r_result2 = padd_gen.remove_padding(&expected2, 8).unwrap_or(&wrong);
	assert_eq!(r_result2, text2);

	let text3: [u8; 8] = [0xAA, 0xCC, 0xEE, 0x48, 0x13, 0xFF, 0x11, 0xDD];
	let expected3 =      [0xAA, 0xCC, 0xEE, 0x48, 0x13, 0xFF, 0x11, 0xDD, 08, 08, 08, 08, 08, 08, 08, 08];
	let s_result3 = padd_gen.set_padding(&text3, 8).unwrap_or(Vec::new());;
	assert_eq!(s_result3, expected3.to_vec());
	let r_result3 = padd_gen.remove_padding(&expected3, 8).unwrap_or(&wrong);
	assert_eq!(r_result3, text3);

	let text4: [u8; 10] = [0x10, 0xCC, 0x73, 0xBB, 0x13, 0xFF, 0x11, 0xDD, 0x50, 0x24];
	let expected4 =       [0x10, 0xCC, 0x73, 0xBB, 0x13, 0xFF, 0x11, 0xDD, 0x50, 0x24, 06, 06, 06, 06, 06, 06];
	let s_result4 = padd_gen.set_padding(&text4, 8).unwrap_or(Vec::new());;
	assert_eq!(s_result4, expected4.to_vec());
	let r_result4 = padd_gen.remove_padding(&expected4, 8).unwrap_or(&wrong);
	assert_eq!(r_result4, text4);
}

#[test]
fn pkcs7_block_16() {
	let padd_gen = PKCS7;
	let wrong = [00];

	let text1: [u8; 0] = [];
	let expected1 =      [16; 16];
	let s_result1 = padd_gen.set_padding(&text1, 16).unwrap_or(Vec::new());;
	assert_eq!(s_result1, expected1.to_vec());
	let r_result1 = padd_gen.remove_padding(&expected1, 16).unwrap_or(&wrong);
	assert_eq!(r_result1, text1);

	let text2: [u8; 5] = [0xAA, 0xCC, 0xEE, 0xBB, 0x13];
	let expected2 =  vec![0xAA, 0xCC, 0xEE, 0xBB, 0x13, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11];
	let s_result2 = padd_gen.set_padding(&text2, 16).unwrap_or(Vec::new());;
	assert_eq!(s_result2, expected2.to_vec());
	let r_result2 = padd_gen.remove_padding(&expected2, 16).unwrap_or(&wrong);
	assert_eq!(r_result2, text2);

	let text3: [u8; 8] = [0xAA, 0xCC, 0xEE, 0x48, 0x13, 0xFF, 0x11, 0xDD];
	let expected3 =  vec![0xAA, 0xCC, 0xEE, 0x48, 0x13, 0xFF, 0x11, 0xDD, 08, 08, 08, 08, 08, 08, 08, 08];
	let s_result3 = padd_gen.set_padding(&text3, 16).unwrap_or(Vec::new());;
	assert_eq!(s_result3, expected3.to_vec());
	let r_result3 = padd_gen.remove_padding(&expected3, 16).unwrap_or(&wrong);
	assert_eq!(r_result3, text3);

	let text4: [u8; 10] = [0x10, 0xCC, 0x73, 0xBB, 0x13, 0xFF, 0x11, 0xDD, 0x50, 0x24];
	let expected4 =  vec![0x10, 0xCC, 0x73, 0xBB, 0x13, 0xFF, 0x11, 0xDD, 0x50, 0x24, 06, 06, 06, 06, 06, 06];
	let s_result4 = padd_gen.set_padding(&text4, 16).unwrap_or(Vec::new());;
	assert_eq!(s_result4, expected4.to_vec());
	let r_result4 = padd_gen.remove_padding(&expected4, 16).unwrap_or(&wrong);
	assert_eq!(r_result4, text4);

	let text5: [u8; 16] = [0x10, 0xCC, 0x73, 0xBB, 0x13, 0xFF, 0x11, 0xDD, 0x50, 0x24, 0x37, 0x22, 0xF5, 0xD3, 00, 0x1C];
	let expected5 =  vec![0x10, 0xCC, 0x73, 0xBB, 0x13, 0xFF, 0x11, 0xDD, 0x50, 0x24, 0x37, 0x22, 0xF5, 0xD3, 00, 0x1C, 
		16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16];
	let s_result5 = padd_gen.set_padding(&text5, 16).unwrap_or(Vec::new());;
	assert_eq!(s_result5, expected5.to_vec());
	let r_result5 = padd_gen.remove_padding(&expected5, 16).unwrap_or(&wrong);
	assert_eq!(r_result5, text5);

	let text6: [u8; 23] = [0x10, 0xCC, 0x73, 0xBB, 0x13, 0xFF, 0x11, 0xDD, 0x50, 0x24, 0x37, 0x22, 0xF5, 0xD3, 00, 0x1C,
		0xCA, 0x6D, 0x34, 0x66, 0xB1, 0xB1, 0x25];
	let expected6 =  vec![0x10, 0xCC, 0x73, 0xBB, 0x13, 0xFF, 0x11, 0xDD, 0x50, 0x24, 0x37, 0x22, 0xF5, 0xD3, 00, 0x1C, 
		0xCA, 0x6D, 0x34, 0x66, 0xB1, 0xB1, 0x25, 09, 09, 09, 09, 09, 09, 09, 09, 09];
	let s_result6 = padd_gen.set_padding(&text6, 16).unwrap_or(Vec::new());;
	assert_eq!(s_result6, expected6.to_vec());
	let r_result6 = padd_gen.remove_padding(&expected6, 16).unwrap_or(&wrong);
	assert_eq!(r_result6, text6);
}

#[test]
fn pkcs7_block_misc() {
	let padd_gen = PKCS7;
	let wrong = [00];

	let text1: [u8; 0] = [];
	let expected1 =  vec![3; 3];
	let s_result1 = padd_gen.set_padding(&text1, 3).unwrap_or(Vec::new());;
	assert_eq!(s_result1, expected1.to_vec());
	let r_result1 = padd_gen.remove_padding(&expected1, 3).unwrap_or(&wrong);
	assert_eq!(r_result1, text1);

	let text2: [u8; 5] = [0xAA, 0xCC, 0xEE, 0xBB, 0x13];
	let expected2 =  vec![0xAA, 0xCC, 0xEE, 0xBB, 0x13, 02, 02];
	let s_result2 = padd_gen.set_padding(&text2, 7).unwrap_or(Vec::new());;
	assert_eq!(s_result2, expected2.to_vec());
	let r_result2 = padd_gen.remove_padding(&expected2, 7).unwrap_or(&wrong);
	assert_eq!(r_result2, text2);

	let text3: [u8; 8] = [0xAA, 0xCC, 0xEE, 0x48, 0x13, 0xFF, 0x11, 0xDD];
	let expected3 =  vec![0xAA, 0xCC, 0xEE, 0x48, 0x13, 0xFF, 0x11, 0xDD, 03, 03, 03];
	let s_result3 = padd_gen.set_padding(&text3, 11).unwrap_or(Vec::new());;
	assert_eq!(s_result3, expected3.to_vec());
	let r_result3 = padd_gen.remove_padding(&expected3, 11).unwrap_or(&wrong);
	assert_eq!(r_result3, text3);

	let text4: [u8; 10] = [0x10, 0xCC, 0x73, 0xBB, 0x13, 0xFF, 0x11, 0xDD, 0x50, 0x24];
	let expected4 =  vec![0x10, 0xCC, 0x73, 0xBB, 0x13, 0xFF, 0x11, 0xDD, 0x50, 0x24, 02, 02];
	let s_result4 = padd_gen.set_padding(&text4, 6).unwrap_or(Vec::new());;
	assert_eq!(s_result4, expected4.to_vec());
	let r_result4 = padd_gen.remove_padding(&expected4, 6).unwrap_or(&wrong);
	assert_eq!(r_result4, text4);

	let text5: [u8; 16] = [0x10, 0xCC, 0x73, 0xBB, 0x13, 0xFF, 0x11, 0xDD, 0x50, 0x24, 0x37, 0x22, 0xF5, 0xD3, 00, 0x1C];
	let expected5 =  vec![0x10, 0xCC, 0x73, 0xBB, 0x13, 0xFF, 0x11, 0xDD, 0x50, 0x24, 0x37, 0x22, 0xF5, 0xD3, 00, 0x1C, 
		10, 10, 10, 10, 10, 10, 10, 10, 10, 10];
	let s_result5 = padd_gen.set_padding(&text5, 13).unwrap_or(Vec::new());;
	assert_eq!(s_result5, expected5.to_vec());
	let r_result5 = padd_gen.remove_padding(&expected5, 13).unwrap_or(&wrong);
	assert_eq!(r_result5, text5);
}