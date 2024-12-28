use std::{process::Command, sync::{atomic::{AtomicUsize, Ordering}, Arc}, thread, time::Duration};

use rayon::iter::{ParallelBridge, ParallelIterator};

fn main() {
    let charset = "egmqrABINO9=";
    let word_length = 8;

    let iterator = WordIterator::new(charset, word_length);

    let counter = Arc::new(AtomicUsize::new(0));
    let counter_clone = Arc::clone(&counter);

    // Start a thread to report performance
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(1));
        let count = counter_clone.swap(0, Ordering::Relaxed);
        println!("Rate: {} passwords/sec", count);
    });

    let found = iterator
        .par_bridge() // Nutzt Rayon, um die Iteration zu parallelisieren
        .find_any(|password| {
            counter.fetch_add(1, Ordering::Relaxed);
            // println!("Trying {}", password);
            if test_password(password.as_str()) {
                println!("Found password: {}", password);
                true
            } else {
                false
            }
        });

    match found {
        Some(password) => println!("Password gefunden: {}", password),
        None => println!("Exhausted all possibilities. No password found."),
    }

    println!("Exhausted all possibilities. No password found.");
}

fn test_password(password: &str) -> bool {
    let output = Command::new("openssl")
        .arg("ec")
        .arg("-in")
        .arg("../openvpn.config")
        .arg("-out")
        .arg("decrypted.key")
        .arg("-passin")
        .arg(format!("pass:{}", password))
        // .stdout(Stdio::inherit())
        // .stderr(Stdio::inherit())
        .output();

    match output {
        Ok(output) => {
            if output.status.success() {
                return true;
            }
        }
        Err(e) => {
            eprintln!("Error executing command: {}", e);
            return false;
        }
    }
    return false;
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
