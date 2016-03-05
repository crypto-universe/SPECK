#![allow(unused_parens)]

use padding::*;

pub struct PKCS7;

impl PaddingGenerator<u8> for PKCS7 {
	fn set_padding (&self, plaintext: &[u8], padding: &mut[u8], block_len: usize) {
		assert!(block_len != 0 && block_len < 256, "Sorry, wrong block length!");
		assert!(padding.len() == block_len, "Padding lenght should be equal to block length!");

		let length: usize = plaintext.len();
		let appendix: usize = length % block_len;
		let padding_size: usize = (block_len - appendix);

		//Clone common u8 to result (padding)
		padding[0..appendix].clone_from_slice(&plaintext[length-appendix..length]);

		for x in &mut padding[appendix..] {
			*x = padding_size as u8;
		}
	}

	fn remove_padding (&self, ciphertext: &[u8], block_len: usize) -> Result<usize, PaddingError> {
		if (ciphertext.is_empty() || ciphertext.len() % block_len != 0) {
			return Err(PaddingError::WrongCiphertextLength);
		}

		let cl = ciphertext.len();
		let padding_size: u8 = ciphertext[cl - 1];

		let (text, padding) = ciphertext.split_at(cl - padding_size as usize);

		match padding.iter().all(|&x| x == padding_size) {
			true  => Ok(text.len()),
			false => Err(PaddingError::WrongPadding),
		}
	}
}

#[test]
fn pkcs7_block_8() {
	const B: usize = 8;
	let padd_gen = PKCS7;
	let mut s_result: [u8; B] = [0; B];

	let text1: [u8; 0] = [];
	let expected1 = [08; 08];
	padd_gen.set_padding(&text1, &mut s_result, B);
	assert_eq!(s_result, expected1);
	let r_result1: usize = padd_gen.remove_padding(&expected1, B).unwrap();
	assert_eq!(r_result1, text1.len());

	let text2: [u8; 5] = [0xAA, 0xCC, 0xEE, 0xBB, 0x13];
	let expected2 =     [0xAA, 0xCC, 0xEE, 0xBB, 0x13, 03, 03, 03];
	padd_gen.set_padding(&text2, &mut s_result, B);
	assert_eq!(s_result, expected2);
	let r_result2: usize = padd_gen.remove_padding(&expected2, B).unwrap();
	assert_eq!(r_result2, text2.len());

	let text3: [u8; 8] = [0xAA, 0xCC, 0xEE, 0x48, 0x13, 0xFF, 0x11, 0xDD];
	let expected3 =      [0xAA, 0xCC, 0xEE, 0x48, 0x13, 0xFF, 0x11, 0xDD, 08, 08, 08, 08, 08, 08, 08, 08];
	padd_gen.set_padding(&text3, &mut s_result, B);
	assert_eq!(s_result, &expected3[8..16]);
	let r_result3: usize = padd_gen.remove_padding(&expected3, B).unwrap();
	assert_eq!(r_result3, text3.len());

	let text4: [u8; 10] = [0x10, 0xCC, 0x73, 0xBB, 0x13, 0xFF, 0x11, 0xDD, 0x50, 0x24];
	let expected4 =       [0x10, 0xCC, 0x73, 0xBB, 0x13, 0xFF, 0x11, 0xDD, 0x50, 0x24, 06, 06, 06, 06, 06, 06];
	padd_gen.set_padding(&text4, &mut s_result, B);
	assert_eq!(s_result, &expected4[8..16]);
	let r_result4: usize = padd_gen.remove_padding(&expected4, B).unwrap();
	assert_eq!(r_result4, text4.len());
}

#[test]
fn pkcs7_block_16() {
	const B: usize = 16;
	let padd_gen = PKCS7;
	let mut s_result: [u8; B] = [0; B];

	let text1: [u8; 0] = [];
	let expected1      = [16; 16];
	padd_gen.set_padding(&text1, &mut s_result, B);
	assert_eq!(s_result, expected1);
	let r_result1 = padd_gen.remove_padding(&expected1, B).unwrap();
	assert_eq!(r_result1, text1.len());

	let text2: [u8; 5] = [0xAA, 0xCC, 0xEE, 0xBB, 0x13];
	let expected2      = [0xAA, 0xCC, 0xEE, 0xBB, 0x13, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11];
	padd_gen.set_padding(&text2, &mut s_result, B);
	assert_eq!(s_result, expected2);
	let r_result2 = padd_gen.remove_padding(&expected2, B).unwrap();
	assert_eq!(r_result2, text2.len());

	let text3: [u8; 8] = [0xAA, 0xCC, 0xEE, 0x48, 0x13, 0xFF, 0x11, 0xDD];
	let expected3      = [0xAA, 0xCC, 0xEE, 0x48, 0x13, 0xFF, 0x11, 0xDD, 08, 08, 08, 08, 08, 08, 08, 08];
	padd_gen.set_padding(&text3, &mut s_result, B);
	assert_eq!(s_result, expected3);
	let r_result3 = padd_gen.remove_padding(&expected3, B).unwrap();
	assert_eq!(r_result3, text3.len());

	let text4: [u8; 10] = [0x10, 0xCC, 0x73, 0xBB, 0x13, 0xFF, 0x11, 0xDD, 0x50, 0x24];
	let expected4       = [0x10, 0xCC, 0x73, 0xBB, 0x13, 0xFF, 0x11, 0xDD, 0x50, 0x24, 06, 06, 06, 06, 06, 06];
	padd_gen.set_padding(&text4, &mut s_result, B);
	assert_eq!(s_result, expected4);
	let r_result4 = padd_gen.remove_padding(&expected4, B).unwrap();
	assert_eq!(r_result4, text4.len());

	let text5: [u8; 16] = [0x10, 0xCC, 0x73, 0xBB, 0x13, 0xFF, 0x11, 0xDD, 0x50, 0x24, 0x37, 0x22, 0xF5, 0xD3, 00, 0x1C];
	let expected5       = [0x10, 0xCC, 0x73, 0xBB, 0x13, 0xFF, 0x11, 0xDD, 0x50, 0x24, 0x37, 0x22, 0xF5, 0xD3, 00, 0x1C, 
		16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16];
	padd_gen.set_padding(&text5, &mut s_result, B);
	assert_eq!(s_result, &expected5[16..32]);
	let r_result5 = padd_gen.remove_padding(&expected5, B).unwrap();
	assert_eq!(r_result5, text5.len());

	let text6: [u8; 23] = [0x10, 0xCC, 0x73, 0xBB, 0x13, 0xFF, 0x11, 0xDD, 0x50, 0x24, 0x37, 0x22, 0xF5, 0xD3, 00, 0x1C,
		0xCA, 0x6D, 0x34, 0x66, 0xB1, 0xB1, 0x25];
	let expected6      = [0x10, 0xCC, 0x73, 0xBB, 0x13, 0xFF, 0x11, 0xDD, 0x50, 0x24, 0x37, 0x22, 0xF5, 0xD3, 00, 0x1C, 
		0xCA, 0x6D, 0x34, 0x66, 0xB1, 0xB1, 0x25, 09, 09, 09, 09, 09, 09, 09, 09, 09];
	padd_gen.set_padding(&text6, &mut s_result, B);
	assert_eq!(s_result, &expected6[16..32]);
	let r_result6 = padd_gen.remove_padding(&expected6, B).unwrap();
	assert_eq!(r_result6, text6.len());
}

#[test]
fn pkcs7_block_misc() {
	let padd_gen = PKCS7;

	let text1: [u8; 0] = [];
	let expected1      = [3; 3];
	let mut s_result1  = [0; 3];
	padd_gen.set_padding(&text1, &mut s_result1, 3);
	assert_eq!(s_result1, expected1);
	let r_result1 = padd_gen.remove_padding(&expected1, 3).unwrap();
	assert_eq!(r_result1, text1.len());

	let text2: [u8; 5] = [0xAA, 0xCC, 0xEE, 0xBB, 0x13];
	let expected2      = [0xAA, 0xCC, 0xEE, 0xBB, 0x13, 02, 02];
	let mut s_result2  = [0; 7];
	padd_gen.set_padding(&text2, &mut s_result2, 7);
	assert_eq!(s_result2, expected2);
	let r_result2 = padd_gen.remove_padding(&expected2, 7).unwrap();
	assert_eq!(r_result2, text2.len());

	let text3: [u8; 8] = [0xAA, 0xCC, 0xEE, 0x48, 0x13, 0xFF, 0x11, 0xDD];
	let expected3      = [0xAA, 0xCC, 0xEE, 0x48, 0x13, 0xFF, 0x11, 0xDD, 03, 03, 03];
	let mut s_result3  = [0; 11];
	padd_gen.set_padding(&text3, &mut s_result3, 11);
	assert_eq!(s_result3, expected3);
	let r_result3 = padd_gen.remove_padding(&expected3, 11).unwrap();
	assert_eq!(r_result3, text3.len());

	let text4: [u8; 10] = [0x10, 0xCC, 0x73, 0xBB, 0x13, 0xFF, 0x11, 0xDD, 0x50, 0x24];
	let expected4       = [0x10, 0xCC, 0x73, 0xBB, 0x13, 0xFF, 0x11, 0xDD, 0x50, 0x24, 02, 02];
	let mut s_result4   = [0; 6];
	padd_gen.set_padding(&text4, &mut s_result4, 6);
	assert_eq!(s_result4, &expected4[6..12]);
	let r_result4 = padd_gen.remove_padding(&expected4, 6).unwrap();
	assert_eq!(r_result4, text4.len());

	let text5: [u8; 16] = [0x10, 0xCC, 0x73, 0xBB, 0x13, 0xFF, 0x11, 0xDD, 0x50, 0x24, 0x37, 0x22, 0xF5, 0xD3, 00, 0x1C];
	let expected5       = [0x10, 0xCC, 0x73, 0xBB, 0x13, 0xFF, 0x11, 0xDD, 0x50, 0x24, 0x37, 0x22, 0xF5, 0xD3, 00, 0x1C, 
		10, 10, 10, 10, 10, 10, 10, 10, 10, 10];
	let mut s_result5   = [0; 13];
	padd_gen.set_padding(&text5, &mut s_result5, 13);
	assert_eq!(s_result5, &expected5[13..26]);
	let r_result5 = padd_gen.remove_padding(&expected5, 13).unwrap();
	assert_eq!(r_result5, text5.len());
}
