use std::iter::FromIterator;
use std::ops::BitXor;

const BYTES_IN_BLOCK: usize   = 16;
const LAST_BLOCK_MASK: u64    = 0xff;

#[derive(Clone, Copy, Debug)]
pub struct Block128 {
	a: u64,
	b: u64,
}

impl Block128 {
	pub fn new (in1: u64, in2: u64) -> Block128 {
		Block128 {a: in1, b: in2}
	}

	pub fn to_block_iter<I: ExactSizeIterator<Item=u8>>(source: I) -> Block128Iter<I> {
		Block128Iter::new(source)
	}

	pub fn to_byte_iter<J: ExactSizeIterator<Item=Block128>>(source: J) -> Byte128Iter<J> {
		Byte128Iter::new(source)	//like FlatMap
	}

	pub fn get_a(&self) -> u64 {
		self.a
	}

	pub fn get_b(&self) -> u64 {
		self.b
	}
}

impl PartialEq for Block128 {
	fn eq(&self, other: &Block128) -> bool {
		self.a == other.get_a() && self.b == other.get_b()
	}

	fn ne(&self, other: &Block128) -> bool {
		self.a != other.get_a() || self.b != other.get_b()
	}
}

impl BitXor for Block128 {
	type Output = Block128;

	fn bitxor(self, rhs: Block128) -> Block128 {
		Block128::new(self.a ^ rhs.get_a(), self.b ^ rhs.get_b())
	}
}

impl IntoIterator for Block128 {
	type Item = u8;
	type IntoIter = ::std::vec::IntoIter<Self::Item>;

	fn into_iter(self) -> Self::IntoIter {
		use std::ops::{BitAnd, Shr};
		let mut result: Vec<Self::Item> = Vec::with_capacity(BYTES_IN_BLOCK);
		//Why I don't care about endianess of current hardware?
		//Regardless of the platform, value in variable is always loaded correctly.
		//While I use "self.a", eberything is going to be OK.
		let mut a1 = self.a.swap_bytes();
		let mut b1 = self.b.swap_bytes();
		while a1 != 0 {
			result.push(a1.bitand(LAST_BLOCK_MASK) as Self::Item);
			a1 = a1.shr(8); 
		}
		while b1 != 0 {
			result.push(b1.bitand(LAST_BLOCK_MASK) as Self::Item);
			b1 = b1.shr(8); 
		}
		result.into_iter()
	}
}

impl FromIterator<u8> for Block128 {
	fn from_iter<I: IntoIterator<Item=u8>>(iterator: I) -> Block128 {
		use std::ops::Shl;
		let mut iter = iterator.into_iter();
		let mut a: u64 = 0;

		for _ in 0..8 {
			a = a.shl(8);
			a = a.bitxor(iter.next().unwrap() as u64)
		}

		let mut b: u64 = 0;

		for _ in 0..8 {
			b = b.shl(8);
			b = b.bitxor(iter.next().unwrap() as u64)
		}
		
		Block128::new(a, b)
	}
}
//======================================================================================================================
pub struct Block128Iter<J> {
	src_iter: J,
	index: usize,
}

impl<J> Block128Iter<J> where J: ExactSizeIterator<Item=u8> {
	pub fn new(src: J) -> Block128Iter<J> {
		let my_len = src.len()/BYTES_IN_BLOCK;
		Block128Iter::<J> {src_iter: src, index: my_len}
	}
}

impl<J> Iterator for Block128Iter<J> where J: ExactSizeIterator<Item=u8> {
	type Item = Block128;

	fn next(&mut self) -> Option<Self::Item> {
		if self.index > 0 {
			self.index -= 1;
			Some(self.src_iter.by_ref().collect())
		} else {
			None
		}
	}
}

impl<J> ExactSizeIterator for Block128Iter<J> where J: ExactSizeIterator<Item=u8> {
	fn len(&self) -> usize {
		self.src_iter.len() / BYTES_IN_BLOCK
	}
}
//======================================================================================================================
pub struct Byte128Iter<K> {
	src_iter: K,
	current: <Block128 as IntoIterator>::IntoIter,
}

impl<K> Byte128Iter<K> where K: ExactSizeIterator<Item=Block128> {
	pub fn new(mut src: K) -> Byte128Iter<K> {
		let curr = src.by_ref().next().unwrap();
		Byte128Iter::<K> {src_iter: src, current: Block128::into_iter(curr)}
	}
}

impl<K> Iterator for Byte128Iter<K> where K: ExactSizeIterator<Item=Block128> {
	type Item = u8;

	fn next(&mut self) -> Option<Self::Item> {
//		use std::iter::Iterator;
		match self.current.next() {
			e @ Some(_) => e,
			None => {
				match self.src_iter.next() {
					Some(block) => {
						self.current = Block128::into_iter(block);
						self.current.next()
					},
					None => None,
				}
			},
		}
	}
}

impl<K> ExactSizeIterator for Byte128Iter<K> where K: ExactSizeIterator<Item=Block128> {
	fn len(&self) -> usize {
		self.src_iter.len() * BYTES_IN_BLOCK
	}
}
//======================================================================================================================
#[test]
fn block128_works1() {
	let init_a: u64 = 0x1D698FDCED742594;
	let init_b: u64 = 0x78BCB34D52D1B961;
	let mut b = Block128::new(init_a, init_b).into_iter();

	//I expect correct byte order!
	let er: [u8; BYTES_IN_BLOCK] = [0x1D, 0x69, 0x8F, 0xDC, 0xED, 0x74, 0x25, 0x94, 0x78, 0xBC, 0xB3, 0x4D, 0x52, 0xD1, 0xB9, 0x61];
	let mut expected = er.iter().cloned();
	for _ in 0..BYTES_IN_BLOCK {
		assert_eq!(b.next(), expected.next());
	}
}

#[test]
fn block128_works2() {
	let src: [u8; BYTES_IN_BLOCK] = [0x1D, 0x69, 0x8F, 0xDC, 0xED, 0x74, 0x25, 0x94, 0x78, 0xBC, 0xB3, 0x4D, 0x52, 0xD1, 0xB9, 0x61];

	let block = Block128::from_iter(src.iter().cloned());
	let mut b = block.into_iter();

	let mut expected = src.into_iter().cloned();
	for _ in 0..BYTES_IN_BLOCK {
		assert_eq!(b.next(), expected.next());
	}
}

#[test]
fn block128_works3() {
	let src: [u8; BYTES_IN_BLOCK*2] =  [0x1D, 0x69, 0x8F, 0xDC, 0xED, 0x74, 0x25, 0x94, 0x78, 0xBC, 0xB3, 0x4D, 0x52, 0xD1, 0xB9, 0x61,
										0xD2, 0xC4, 0xB7, 0xD9, 0x6C, 0x49, 0x16, 0x0E, 0x4E, 0xFE, 0x0C, 0x3E, 0x3B, 0x9F, 0xFD, 0x85];

	let mut src_iter = src.iter();
	//There are 2 ways to get Block128 from iterator:
	let block1: Block128 = src_iter.by_ref().cloned().collect();
	let block2 = Block128::from_iter(src_iter.by_ref().cloned());
	let mut b1 = block1.into_iter();
	let mut b2 = block2.into_iter();

	let mut expected = src.into_iter().cloned();
	for _ in 0..BYTES_IN_BLOCK {
		assert_eq!(b1.next(), expected.next());
	}
	for _ in 0..BYTES_IN_BLOCK {
		assert_eq!(b2.next(), expected.next());
	}
}

#[test]
fn block128_works4() {
	let src: [u8; BYTES_IN_BLOCK*3] =  [0x1D, 0x69, 0x8F, 0xDC, 0xED, 0x74, 0x25, 0x94, 0x78, 0xBC, 0xB3, 0x4D, 0x52, 0xD1, 0xB9, 0x61,
										0xD2, 0xC4, 0xB7, 0xD9, 0x6C, 0x49, 0x16, 0x0E, 0x4E, 0xFE, 0x0C, 0x3E, 0x3B, 0x9F, 0xFD, 0x85,
										0x10, 0xCC, 0x73, 0xBB, 0x13, 0xFF, 0x11, 0xDD, 0x50, 0x24, 0x37, 0x22, 0xF5, 0xD3, 0x00, 0x1C];

	let src_iter = src.iter().cloned();
	let mut expected = src.iter().cloned();

	for block in Block128::to_block_iter(src_iter) {
		for b in block {
			assert_eq!(b, expected.next().unwrap());
		}
	}
}
