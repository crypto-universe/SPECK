//Block is just a wrapper over unstable u128

use std::ops::BitXor;

pub const BYTES_IN_BLOCK: usize = 16;

#[derive(Clone, Debug, PartialEq)]
pub struct Block128(u128);

// TODO: Make a trait for these functions
impl Block128 {
	pub fn get_a(&self) -> u64 {
		(self.0 >> 64) as u64
	}

	pub fn get_b(&self) -> u64 {
		self.0 as u64
	}
}

impl BitXor for Block128 {
	type Output = Block128;

	fn bitxor(self, rhs: Self) -> Self {
		Block128(self.0 ^ rhs.0)
	}
}

// Should I use 'to_owned' for slices? "From"" must consume argument...
impl<'a> From<&'a [u8; 16]> for Block128 {
	fn from(slice: &[u8; 16]) -> Block128 {
		let value: u128;
		unsafe {
			value = *(slice.as_ptr() as *const u128);
		}
		Block128(value.to_be())
	}
}

impl<'a> From<&'a [u8]> for Block128 {
	fn from(slice: &[u8]) -> Block128 {
		assert!(slice.len() == 16, "Slice must have 16 bytes!");
		let value: u128;
		unsafe {
			value = *(slice.as_ptr() as *const u128);
		}
		Block128(value.to_be())
	}
}

impl<'a> From<&'a [u64; 2]> for Block128 {
	fn from(slice: &'a [u64; 2]) -> Block128 {
		Block128((slice[0] as u128) << 64 | (slice[1] as u128))
	}
}

impl From<u128> for Block128 {
	fn from(val: u128) -> Block128 {
		Block128(val)
	}
}

impl<'a> From<&'a Block128> for Block128 {
	fn from(val: &'a Block128) -> Block128 {
		Block128(val.0)
	}
}

impl From<Block128> for Vec<u8> {
	fn from(block: Block128) -> Vec<u8> {
		let mut value: u128 = block.0.swap_bytes();	//We need reverse order to push in vector
		let mut result: Vec<u8> = Vec::with_capacity(BYTES_IN_BLOCK);
		for _i in 0..BYTES_IN_BLOCK {
			result.push(value as u8);
			value >>= 8;
		}
		result
	}
}

impl AsRef<[u8]> for Block128 {
	#[inline]
	fn as_ref(&self) -> &[u8] {
		unsafe { ::std::slice::from_raw_parts(&self.0 as *const u128 as *const u8, BYTES_IN_BLOCK) }
	}
}

#[test]
fn block128_works1() {
	let input1: u128 = 0x7469206564616d206c61766975716520;
	let block1: Block128 = Block128(input1);
	let output1: Vec<u8> = block1.into();
	let expected1: &[u8] = &[0x74, 0x69, 0x20, 0x65, 0x64, 0x61, 0x6d, 0x20, 0x6c, 0x61, 0x76, 0x69, 0x75, 0x71, 0x65, 0x20];

	assert_eq!(output1.as_slice(), expected1);
}

#[test]
fn block128_works2() {
	let input1: &[u8; 16] = &[0x74, 0x69, 0x20, 0x65, 0x64, 0x61, 0x6d, 0x20, 0x6c, 0x61, 0x76, 0x69, 0x75, 0x71, 0x65, 0x20];
	let block1: Block128 = Block128::from(input1);
	let output1: u128 = block1.0;
	let expected1: u128 = 0x7469206564616d206c61766975716520;

	assert_eq!(output1, expected1);
}

#[test]
fn block128_works3() {
	let input1: u128 = 0x7469206564616d206c61766975716520;
	let block1: Block128 = Block128(input1);
	let output_a: u64 = block1.get_a();
	let output_b: u64 = block1.get_b();
	let expected_a: u64 = 0x7469206564616d20;
	let expected_b: u64 = 0x6c61766975716520;

	assert_eq!(output_a, expected_a);
	assert_eq!(output_b, expected_b);
}

#[test]
#[should_panic]
fn block128_panic() {
	//Should fail on 15 bytes
	let input1: &[u8] = &[0x74, 0x69, 0x20, 0x65, 0x61, 0x6d, 0x20, 0x6c, 0x61, 0x76, 0x69, 0x75, 0x71, 0x65, 0x20];
	let block1: Block128 = Block128::from(input1);
	assert_eq!(block1.0, 0x74692065616d206c61766975716520);
}