pub fn bytes_to_words(input: &[u8]/*, word_len: usize*/) -> &[u64] {
	//It can be zero-length slice.
	//Don't forget about endianess!
	unsafe { ::std::slice::from_raw_parts(&input[0] as *const u8 as *const u64, input.len() / 8) }
}

pub fn words_to_bytes(input: &[u64]) -> &[u8] {
	//Don't forget about endianess!
	unsafe { ::std::slice::from_raw_parts(&input[0] as *const u64 as *const u8, input.len() * 8) }
}
/*
fn word_to_bytes(input: u64) -> [u8; 8] {
	unsafe{::std::mem::transmute(input)}
}*/

//TODO: remove!
pub fn my_extend_from_slice(input: &mut Vec<u8>, elements: &[u8]) {
	for x in elements {
		input.push(*x);
	}
}