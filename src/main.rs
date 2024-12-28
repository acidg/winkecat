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
use rayon::iter::{ParallelBridge, ParallelIterator};

const CONFIG_PATH: &str = "../privatekey.pem";

fn main() {
    const CHARSET: &str = "egmqrABINO09=";
    const WORD_LENGTH: usize = 8;

    // Read the encrypted data from the file
    let confg_file = read(CONFIG_PATH).unwrap();

    // Iterator to generate password combinations
    let iterator = WordIterator::new(CHARSET, WORD_LENGTH);

    let counter = Arc::new(AtomicUsize::new(0));
    let counter_clone = Arc::clone(&counter);

    // Spawn a thread for monitoring performance
    thread::spawn(move || {
        let total: u64 = 0;
        loop {
            thread::sleep(Duration::from_secs(1));
            let count = counter_clone.swap(0, Ordering::Relaxed);
            println!("Elapsed: {}, Rate: {} passwords/sec", total, count);
        }
    });

    // Search for the correct password
    let found = iterator
        .par_bridge() // Parallelized iteration using Rayon
        .find_any(|password| {
            counter.fetch_add(1, Ordering::Relaxed);
            if test_password(&confg_file, password.as_str()) {
                println!("Found password: {}", password);
                true
            } else {
                false
            }
        });

    match found {
        Some(password) => println!("Password found: {}", password),
        None => println!("Exhausted all possibilities. No password found."),
    }
}

fn test_password(confg_file: &Vec<u8>, password: &str) -> bool {
    match EcKey::private_key_from_pem_passphrase(&confg_file, password.as_bytes()) {
        Ok(_) => {
            return true;
        }
        Err(e) => {
            if e.errors()[0].reason() == Some("bad decrypt") {
                return false;
            }
            return false;
        }, // Password was incorrect
    }
}

struct WordIterator {
    charset: Vec<char>,
    current: Vec<usize>,
    length: usize,
    finished: bool,
}

impl WordIterator {
    pub fn new(charset: &str, length: usize) -> Self {
        Self {
            charset: charset.chars().collect(),
            current: vec![0; length],
            length,
            finished: false,
        }
    }
}

impl Iterator for WordIterator {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        // Construct the current word
        let word: String = self.current.iter().map(|&i| self.charset[i]).collect();

        // Update the current state
        for i in (0..self.length).rev() {
            if self.current[i] + 1 < self.charset.len() {
                self.current[i] += 1;
                break;
            } else {
                self.current[i] = 0;
                if i == 0 {
                    self.finished = true;
                }
            }
        }

        Some(word)
    }
}
