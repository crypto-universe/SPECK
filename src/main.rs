#![allow(non_camel_case_types)]
#![allow(dead_code)]
// 128/128

const ALPHA:   u8 = 8;
const BETA:    u8 = 3;
const KEY_LEN: usize = 2;
const ROUNDS:  usize = 32;

fn main() {
    println!("THIS IS SPECK 128/128 !");
    
    let PLAINTEXT: [u64; 2] = [0x7469206564616d20, 0x6c61766975716520];
    let KEY: [u64; KEY_LEN] = [0x0706050403020100, 0x0f0e0d0c0b0a0908];
    
    println!("Plaintext:  {:x} {:x}", PLAINTEXT[0], PLAINTEXT[1]);
    println!("Key:        {:x} {:x}", KEY[0], KEY[1]);
    
    let mut KEYS_PROP: [u64; ROUNDS] = [0; ROUNDS];
	key_schedule(&KEY, &mut KEYS_PROP);
	
	assert!   (KEYS_PROP[ROUNDS-2] == 0xc53d18b91770b265);
	assert_eq!(KEYS_PROP[ROUNDS-1],   0x2199c870db8ec93f);
	
	//let mut : [u64; 2] = [0; 2];
	
	let ciphertext: [u64; 2] = speck_encrypt(&PLAINTEXT, &KEYS_PROP);
	assert_eq!(ciphertext[0], 0x7860fedf5c570d18);
	assert_eq!(ciphertext[1], 0xa65d985179783265);
	println!("Ciphertext: {:x} {:x}", ciphertext[0], ciphertext[1]);

	let decryptedtext: [u64; 2] = speck_decrypt(&ciphertext, &KEYS_PROP);
	assert_eq!(decryptedtext[0], PLAINTEXT[0]);
	assert_eq!(decryptedtext[1], PLAINTEXT[1]);
	println!("Decrypted:  {:x} {:x}", decryptedtext[0], decryptedtext[1]);
}

fn key_schedule(key: &[u64; KEY_LEN], propagated: &mut [u64; ROUNDS]) {
	let mut y: [u64; KEY_LEN] = [key[1], key[0]];
	propagated[0] = key[0];
	for i in 1..ROUNDS {
		speck_round_forward(&mut y, (i-1) as u64);
		propagated[i] = y[1];
	}
}

fn speck_encrypt(plaintext: &[u64; 2], keys: &[u64; ROUNDS]) -> [u64; 2]{
    let mut ciphertext: [u64; 2] = [plaintext[1], plaintext[0]];

	for i in 0..ROUNDS {
		speck_round_forward(&mut ciphertext, keys[i]);
	}
	
	[ciphertext[1], ciphertext[0]]
}

fn speck_decrypt(ciphertext: &[u64; 2], keys: &[u64; ROUNDS]) -> [u64; 2]{
    let mut decrypted: [u64; 2] = [ciphertext[1], ciphertext[0]];

	for i in (0..ROUNDS).rev() {
		speck_round_backward(&mut decrypted, keys[i]);
	}
	
	[decrypted[1], decrypted[0]]
}

#[inline(always)]
fn speck_round_forward(x: &mut [u64; 2], key: u64) {
	x[0] = ((ror(x[0], ALPHA)).wrapping_add(x[1])) ^ key;
	x[1] = rol(x[1], BETA) ^ (x[0]);
}

#[inline(always)]
fn speck_round_backward(x: &mut [u64; 2], key: u64) {
	x[1] = ror((x[1] ^ x[0]), BETA);
	x[0] = rol(((x[0] ^ key).wrapping_sub(x[1])), ALPHA);
}

#[inline(always)]
fn rol(num: u64, amount: u8) -> u64 {
	(num << amount) | (num >> (64-amount))
}

#[inline(always)]
fn ror(num: u64, amount: u8) -> u64 {
	(num >> amount) | (num << (64-amount))
}
