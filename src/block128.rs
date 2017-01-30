//Block is just a wrapper over unstable u128
pub struct Block128(u128);

impl Block128 {
	pub fn get_a(&self) -> u64 {
		(self.0 >> 64) as u64
	}

	pub fn get_b(&self) -> u64 {
		self.0 as u64
	}
}

impl<'a> From<&'a [u8]> for Block128 {
    fn from(slice: &[u8]) -> Self {
		assert!(slice.len() >= 16, "Slice must have at least 16 bytes!");
		let value: u128;
		unsafe {
			value = *(&slice[0] as *const u8 as *const u128);
		}
		Block128(value.to_be())
    }
}

impl Into<[u8; 16]> for Block128 {
	fn into(self) -> [u8; 16] {
		let mut value: u128 = self.0;
		let mut result: [u8; 16] = [0u8; 16];
		for i in (0..16).rev() {
			result[i] = value as u8;
			value >>= 8;
		}
		result
	}
}

#[test]
fn block128_works1() {
	let input1: u128 = 0x7469206564616d206c61766975716520;
	let block1: Block128 = Block128(input1);
	let output1: [u8; 16] = block1.into();
	let expected1: &[u8] = &[0x74, 0x69, 0x20, 0x65, 0x64, 0x61, 0x6d, 0x20, 0x6c, 0x61, 0x76, 0x69, 0x75, 0x71, 0x65, 0x20];

	assert_eq!(&output1, expected1);
}

#[test]
fn block128_works2() {
	let input1: &[u8] = &[0x74, 0x69, 0x20, 0x65, 0x64, 0x61, 0x6d, 0x20, 0x6c, 0x61, 0x76, 0x69, 0x75, 0x71, 0x65, 0x20];
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
	let expected_b: u64 = 0x206c61766975716520;

	assert_eq!(output_a, expected_a);
	assert_eq!(output_b, expected_b);
}

#[test]
#[should_panic]
fn block128_panic() {
	//Should fail on 15 bytes
	let input1: &[u8] = &[0x74, 0x69, 0x20, 0x65, 0x61, 0x6d, 0x20, 0x6c, 0x61, 0x76, 0x69, 0x75, 0x71, 0x65, 0x20];
	let block1: Block128 = Block128::from(input1);
	assert_eq!(block1.0, 0x74692065616d206c61766975716520;);
}