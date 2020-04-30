//! A Basic Blockchain - Billcoin
//!
//! In this exercise, we'll walk through a very basic blockchain, which
//! contains a single transaction per block, has a magic address which
//! generates as many billcoins as you like, has no cryptographic protection,
//! and just uses a simple hash to keep things in line.  But still, it's
//! a blockchain!
//!
//! The program is relatively simple - just include a single argument to
//! read in the file and it should verify if it valid or not.
//!
//! As always, go through the TODOs.  I have created several blockchains
//! for you to test your program against and have included the expected output
//! in the root directory (EXPECTED_OUTPUT.TXT).  This time, all of the TODOs
//! are in a single function.
//!
//! You can also run the program without any arguments to generate your own
//! blockchain for testing - simply copy and paste the output into a new file.
//! You will be prompted to enter the from address, amount, and to address
//! of each transaction (and thus block).  Enter "x" for the from address
//! to stop entering blocks and end the program.  Note that no verification
//! happens when generating a blockchain this way!


use std::collections::HashMap;
use std::env;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::fs::File;
use std::io::prelude::*;
use std::io;
use std::io::{BufRead, BufReader};

// Both the address and the amount of billcoins moved are unsigned 64-bit
// integers, although addresses are usually displayed in hex and amounts
// in decimal
type Address = u64;
type Amount = u64;
type Digest = u64;

// For simplicity, every block will have exactly one transaction - for efficiency,
// on a real blockchain, you will generally see 0..n transactions in a block.
// A transaction consists of a "to" address, a "from" address, and amount sent
// A block contains a transaction and the hash of the previous block
// The Debug trait just lets us easily print it out using println!
// The Hash trait allows us to hash a struct of this type

#[derive(Debug, Hash)]
pub struct Block {
    pub to_addr: Address,
    pub from_addr: Address,
    pub amount: Amount,
    pub prev_hash: Digest
}


// Given any object, return its 64-bit hash.  This uses the default
// Rust hashing algorithm.

fn get_hash<T: Hash>(t: &T) -> Digest {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    let r = s.finish();
    r 
}

// Convert a hex string (e.g. "0x1F" or "1F") to a 64-bit unsigned int.
// We use u64 instead of Address or Amount since this works for any
// type which equates to u64.

fn convert_hex(x: String) -> u64 {
    let num = x.trim_start_matches("0x");
    u64::from_str_radix(num, 16).unwrap()
}

// Convert a decimal string (e.g. "31") to a 64-bit unsigned int.
// We use u64 instead of Address or Amount since this works for any
// type which equates to u64.

fn convert_decimal(x: String) -> u64 {
    u64::from_str_radix(&x, 10).unwrap()
}


// Print a blockchain `bc` in human-readable format.

fn pretty_print_blockchain(bc: &Vec<Block>) {
    for (j, b) in bc.iter().enumerate() {
        println!("Block: {}, {:#016x} sent {} billcoins to {:#016x} (Prev Hash: {:#016x})",
                 j,
                 b.from_addr,
                 b.amount,
                 b.to_addr,
                 b.prev_hash);
    }
}

// Print a blockchain `bc` in CSV format for easy ingestion for computers.

fn print_blockchain(bc: &Vec<Block>) {
    for (j, b) in bc.iter().enumerate() {
        println!("{},{:#016x},{},{:#016x},{:#016x}",
                 j,
                 b.from_addr,
                 b.amount,
                 b.to_addr,
                 b.prev_hash);
        
    }
}

// Print how many billcoins every address has.

fn print_results(results: HashMap<Address, Amount>) {
    for (address, amount) in results {
        // 0 is our "magic" source address - ignore it
        if address != 0 && amount != 0 {
            println!("{:#016x} : {} billcoins", address, amount);
        }
    }
}

// Read blockchain from file file_name.
// Note that we don't do much error-checking here in terms of file
// reading - if there are any issues, we are likely to just panic.
// This is more to keep the code simple than anything else.

fn read_file(file_name: &String) -> Vec<Block> {
    let file = File::open(file_name).unwrap();
    let reader = BufReader::new(file);
    let mut blocks: Vec<Block> = Vec::new();

    // Convert every line into a block and add to blockchain
    
    for line in reader.lines() {
        let line = line.unwrap();
        let mut split = line.split(",");

        // Create the block from the line and add it to the blockchain
        // Remember that iterators are consumed, so all the nth(0)'s
        // are reading the next element in line.
        let b = Block {
            from_addr: convert_hex(split.nth(1).unwrap().to_string()),
            amount: convert_decimal(split.nth(0).unwrap().to_string()),
            to_addr: convert_hex(split.nth(0).unwrap().to_string()),
            prev_hash: convert_hex(split.nth(0).unwrap().to_string())
        };
        blocks.push(b);
    }
    blocks
}

// Verify that the blockchain is valid.  If it is, returns a hashmap of all
// the accounts and how many billcoins they have.  If it is invalid,
// returns an error specifying the problem (if known).

fn verify_blockchain(blockchain: &Vec<Block>) -> Result<HashMap<Address, Amount>, String> {
    // TODO 1
    // Create a new HashMap<Address, Amount> and expected_prev_hash to store
    // previous hashes to check.
    let mut balances: HashMap<Address, Amount> = HashMap::new();
    let mut expected_prev_hash = 0;

    // This is a special for loop which will update two variables at each
    // iteration:
    // j - contains an index (i.e., increments from 0,1,2... each iteration)
    // b - will contain the next block each iteration
    
    for (j, b) in blockchain.iter().enumerate() {
        // TODO 1
        // Check to see if address has enough billcoins to actually send
        // The only exception is address 0x0 - this is our magic source address
        // where all billcoins come from.  Anyone can get any number of billcoins
        // from 0x0, it has an inexhaustible supply.
        // Otherwise, there are two possible error conditions - the address
        // does not exist at all, or it has less than the amount of billcoins
        // it is trying to send.  An address with 5 billcoins cannot send 10 to
        // somebody else!


        if b.from_addr != 0 {
            let num_billcoins_result = balances.get(&b.from_addr);
            match num_billcoins_result {
                Some(num_billcoins) => {
                    if num_billcoins < &b.amount {
                        return Err(format!("Line {}: Account {:#016x} only has {} billcoins; it cannot send {}",
                                           j,
                                           b.from_addr,
                                           num_billcoins,
                                           b.amount));
                    }
                },
                None => {
                    return Err(format!("Line {}: Account {:#016x} has 0 billcoins; it cannot send {}",
                                       j,
                                       b.from_addr,
                                       b.amount));
                }
                
            }
            
        }

        // TODO 2

        // Users can never send any billcoins _TO_ address 0x0 - it is only used as a source.
        // If the to_address is 0, raise an error indicating this.

        if b.to_addr == 0 {

            return Err(format!("Line {}: Account {:#016x} tried to send to address 0x00000000000000",
                               j,
                               b.from_addr));
            
        }
        
        // TODO 3
        // Check to see if the prev_hash matches the expected previous hash
        // The first prev_hash should always be 0x0.
        // If not, return an error
        if b.prev_hash != expected_prev_hash {
            return Err(format!("Line {}: Prev hash was expected to be {:#016x}, not {:#016x}",
                               j,
                               expected_prev_hash,
                               b.prev_hash));
        }
        // TODO 4
        
        // Store the hash of this block as the expected previous hash for the
        // next block (iteration of the for loop)
        expected_prev_hash = get_hash(b);
        
        // TODO 5
        
        // If we have gotten here, all is in order.  Update the hash map to indicate
        // that the from_address has lost a certain number of billcoins and the 
        // to_address has gained an equivalent number of billcoins.
        // No coins should ever be subtracted from the 0x0 address
        // HINT: You may find .cloned() and .unwrap_or() helpful when dealing
        // with the hashmap!

        let old_balance_from = balances.get(&b.from_addr).cloned().unwrap_or(0);
        let old_balance_to = balances.get(&b.to_addr).cloned().unwrap_or(0);
        
        if b.from_addr != 0 {
            let new_from_amount = old_balance_from - b.amount;
            balances.insert(b.from_addr, new_from_amount);
        }
        let new_to_amount = old_balance_to + b.amount;
        balances.insert(b.to_addr, new_to_amount);
        
    }

    // TODO 6
    
    // Return hashmap of balances if all is correct

    Ok(balances)

}

// Read and verify blockchain.

fn read_blockchain(f: String) -> Result<HashMap<Address, Amount>, String> {
    let blockchain = read_file(&f);
    pretty_print_blockchain(&blockchain);
    verify_blockchain(&blockchain)
}


// Get block information from the user (from address, to address,
// and amount.  Recall that every block has only a single transaction.
// We also need the previous hash to generate a block, so it is
// passed in as an argument.
//
// User can enter the block data from STDIN.  Type "x" for the "from"
// address to stop generating blocks.
//
// This will return either None (if the block could not be created,
// probably because the user entered "x" because they did not want to
// continue generating the blockchain) or Some(block).

fn get_block_info(prev_hash: Digest) -> Option<Block> {
    let mut to_addr: String = String::new();
    let mut from_addr: String = String::new();
    let mut amount: String = String::new();

    print!("From address (hex) > ");
    let _ = io::stdout().flush();
    io::stdin().read_line(&mut from_addr).unwrap();
    from_addr = from_addr.trim().to_string();
    if from_addr == "x" {
        return None
    }
    print!("To address (hex) > ");
    let _ = io::stdout().flush();
    io::stdin().read_line(&mut to_addr).expect("Error");
    to_addr = to_addr.trim().to_string();
    
    print!("Amount > ");
    let _ = io::stdout().flush();
    io::stdin().read_line(&mut amount).expect("Error");
    amount = amount.trim().to_string();

    // Generate block from input

    let b = Block {
        to_addr: convert_hex(to_addr),
        from_addr: convert_hex(from_addr),
        amount: convert_decimal(amount),
        prev_hash: prev_hash
    };

    Some(b)
        
}

// Generate a blockchain given input from the user (or really, STDIN)

fn make_blockchain() -> Vec<Block> {
    let mut prev_hash = 0;
    
    let mut blockchain: Vec<Block> = Vec::new();

    let mut block_num = 0;
    loop {
        println!("Block Number: {}", block_num);
        
        let block_option = get_block_info(prev_hash);
        match block_option {
            Some(b) => {
                // Get hash of this block to use as prev_hash for
                // NEXT block
                prev_hash = get_hash(&b);

                // Add block to blockchain
                blockchain.push(b);
            },
            None => {
                // Stop collecting blocks from user
                break;
            }
        }
        
        block_num = block_num + 1;

    }

    blockchain
        
}

fn print_usage_and_exit() {
    println!("Usage:");
    println!("No arguments: ");
    println!("One argument: Read file specified by argument and display if blockchain is valid");
    std::process::exit(1);
}

// Execution starts here

fn main() {

    let args_count = env::args().count();
    if args_count <= 1 {
        // If no arguments are supplied, allow user to make a blockchain.
        // It will then be printed out in CSV, and you can copy/paste into a
        // file.
        let blockchain = make_blockchain();
        print_blockchain(&blockchain);
    } else if args_count == 2 {

        // Otherwise, if exactly one argument is given, assume it is a
        // CSV file with blockchain data.
        
        // Note: we know this element exists, otherwise we would
        // have to worry about unwrap() panicking
        let valid = read_blockchain(env::args().nth(1).unwrap());
        
        // If blockchain is valid, print out the final results - which
        // addresses exist and how many billcoins they own
        // Otherwise, say it is invalid (and hopefully why)
        match valid {
            Ok(bc) => {
                print_results(bc);
                println!("Blockchain valid!");
            },
            Err(e) => {
                println!("Blockchain invalid: {}", e);
            }
        } 
        
        
    } else {
        // If more than one argument is there, instruct user how to use
        // program and exit.
        print_usage_and_exit();
    }
}
