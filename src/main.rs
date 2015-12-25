mod speck;



fn main() {
    println!("THIS IS SPECK 128/128 !");
    
    let PLAINTEXT: [u64; 2] = [0x7469206564616d20, 0x6c61766975716520];
    let KEY: [u64; speck::KEY_LEN] = [0x0706050403020100, 0x0f0e0d0c0b0a0908];
    
    println!("Plaintext:  {:x} {:x}", PLAINTEXT[0], PLAINTEXT[1]);
    println!("Key:        {:x} {:x}", KEY[0], KEY[1]);
    
    let mut KEYS_PROP: [u64; speck::ROUNDS] = [0; speck::ROUNDS];
	speck::key_schedule(&KEY, &mut KEYS_PROP);
	
	assert!   (KEYS_PROP[speck::ROUNDS-2] == 0xc53d18b91770b265);
	assert_eq!(KEYS_PROP[speck::ROUNDS-1],   0x2199c870db8ec93f);
	
	//let mut : [u64; 2] = [0; 2];
	
	let ciphertext: [u64; 2] = speck::speck_encrypt(&PLAINTEXT, &KEYS_PROP);
	assert_eq!(ciphertext[0], 0x7860fedf5c570d18);
	assert_eq!(ciphertext[1], 0xa65d985179783265);
	println!("Ciphertext: {:x} {:x}", ciphertext[0], ciphertext[1]);

	let decryptedtext: [u64; 2] = speck::speck_decrypt(&ciphertext, &KEYS_PROP);
	assert_eq!(decryptedtext[0], PLAINTEXT[0]);
	assert_eq!(decryptedtext[1], PLAINTEXT[1]);
	println!("Decrypted:  {:x} {:x}", decryptedtext[0], decryptedtext[1]);
}


