use std::{
    fs::read,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};
use openssl::ec::EcKey;
use rayon::prelude::*;

const CONFIG_PATH: &str = "../privatekey.pem";
const CHARSET: &[u8] = b"egmqrABINO09=";
const WORD_LENGTH: usize = 8;

fn main() {
    let confg_file = read(CONFIG_PATH).expect("Failed to read config file");

    let counter = Arc::new(AtomicUsize::new(0));

    // Spawn a thread for monitoring performance
    let counter_clone = Arc::clone(&counter);
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(1));
            let count = counter_clone.swap(0, Ordering::Relaxed);
            println!("Rate: {} passwords/sec", count);
        }
    });

    // Use Rayon to parallelize password search
    let found = (0..CHARSET.len().pow(WORD_LENGTH as u32))
        .into_par_iter()
        .find_any(|&index| {
            let password = generate_password(index, CHARSET, WORD_LENGTH);
            counter.fetch_add(1, Ordering::Relaxed);
            if EcKey::private_key_from_pem_passphrase(&confg_file, &password).is_ok() {
                println!("Found password: {}", String::from_utf8(password).unwrap());
                true
            } else {
                false
            }
        });

    match found {
        Some(_) => println!("Password search completed."),
        None => println!("Exhausted all possibilities. No password found."),
    }
}

// Generate a password string from an index
fn generate_password(index: usize, charset: &[u8], length: usize) -> Vec<u8> {
    let mut password = vec![0u8; length];
    let base = charset.len();
    let mut idx = index;

    for i in (0..length).rev() {
        password[i] = charset[idx % base];
        idx /= base;
    }

    return password;
}
