use clap::Parser;
use hex;
use sha1::{Digest, Sha1};
use std::fs::File;
use std::io::{BufRead, BufReader};

/// SHA1 hash cracker.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Name of rainbow file.
    #[arg(short, long, default_value_t = String::from("wordlist.txt"))]
    filename: String,
    /// Hash to crack.
    #[arg(long)]
    hash: String,
}

const SHA1_HEX_STRING_LENGTH: usize = 40;

fn main() {
    let args = Args::parse();
    let hash_to_crack = if args.hash.len() != SHA1_HEX_STRING_LENGTH {
        panic!("Hash is insufficiently long.");
    } else {
        args.hash
    };

    let file = match File::open(args.filename) {
        Ok(file) => file,
        Err(e) => panic!("Rainbow file was not read: {}", e),
    };

    let reader = BufReader::new(file);

    let mut flag = false;

    reader.lines().for_each(|l| {
        let prospective_pass = match l {
            Ok(l) => l,
            Err(_e) => panic!("Error in line read."),
        };
        let hashed_pass = hex::encode(Sha1::digest(prospective_pass.trim().as_bytes()));
        if hashed_pass == hash_to_crack {
            println!("Here is the your password: {}", prospective_pass);
            flag = true;
        }
    });
    
    if !flag {
        println!("Password not found.");
    }
}
