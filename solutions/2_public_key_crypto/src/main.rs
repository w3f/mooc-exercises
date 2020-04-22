//! # A Simple Public-Key Implementation
//!
//! IMPORTANT - This should not be used for anything important!
//! The goal of this program is to teach you the basics of public-key cryptography
//! but it has not been audited or protected against other attacks.  Additionally,
//! it is trivially crackable due to the relatively small number of possible
//! keys and does not use industrial-strength randomization.  When using cryptography for
//! any professional purpose, follow this cardinal rule - "don't roll your own crypto!"  
//!
//! ## Overview
//!
//! Although most people think of public-key cryptography as simply encrypting
//! communications, it can also be used to prove that a particular identity
//! wrote something.  As long as the private key is not shared with anybody,
//! then only the person who owns the private key will able to reliably sign messages
//! with it.  This is done in a three-step process, detailed below.
//!
//! ### Key Generation
//!
//! Two keys, a public key and a private key, are produced.  These keys are
//! mathematically linked in a way that we will see in the algorithm.  As their names
//! imply, the public key should be publicly shared and the private key must
//! be kept private.
//!
//! ### Signing
//!
//! Using the message as input, you "sign" it with your private key.  This will
//! produce a number that can prove that you wrote the message.
//!
//! ### Verifying
//!
//! Using the message and the produced signature, anybody can prove that you
//! generated that signature, without knowing the private key, using only
//! the public key.
//!
//! ### Example and Walkthrough
//!
//! ```
//! $ cargo run generate
//! Private key: 902962279, 278653459
//! Public key: 902962279, 291642999
//! 
//! $ cargo run sign meow 902962279 278653459
//! Signature: 124665060
//! 
//! $ cargo run verify meow 124665060 902962279 291642999
//! Signature verified!
//! 
//! $ cargo run verify meow 111111 902962279 291642999
//! SIGNATURE INVALID!
//! ```
//!
//! We can see above that a person, let's call her Alice, has generated a
//! keypair - the private key (902962279, 278653459) which she keeps secret,
//! and a public key (902962279, 291642999) which she publicizes widely to
//! anyone who wants to communicate with her.
//!
//! Alice would like to prove to the world that she wrote the message "meow".
//! Perhaps she insists that she is a cat, or this is a game like
//! rock-paper-scissors.  She can publish "meow" with the signature "124665060"
//! and anyone can look up her public key and prove that she (or at least
//! someone with her private key) wrote it.
//!
//! There are many other uses for signatures in blockchain technology,
//! many of which will be covered later in the course.
//!
//! ## RSA Algorithm
//!
//! This is a relatively straightforward implementation of the paper
//! ["A Method for Obtaining Digital Signatures and Public-Key Cryptosystems"
//! by Rivest, Shamir and Adleman]([https://people.csail.mit.edu/rivest/Rsapaper.pdf]).
//!
//! If some of the terminology seems strange, don't worry, we will go through
//! it step by step in the functions.
//!
//! 1. Choose two different prime numbers, p and q.
//! 2. Compute n = p * q.
//! 3. Compute the Carmichael's totient function (lcm(p - 1, q - 1) to get t.
//! 4. Choose an integer, e, where 1 < e < t and e is coprime to t.
//! 5. Compute the modular multiplicative inverse of e mod t to get d.
//! 6. The public key is (n, e).  The private key is (n, d).
//!
//! To sign a message, we will take a hash of the message and raise it
//! to the power of d modulo n.  To verify a message, we will take the
//! signature and raise it to the power of e modulo n to get a value r.
//! If r == h modulo n, then the signatures match and it is valid; otherwise
//! invalid.

// External crates that we use for a mathematical functions dealing
// with large integers - quite common in cryptography.

extern crate num_bigint;
extern crate num_traits;

use num_bigint::BigUint;
use num_traits::cast::ToPrimitive;

use rand::prelude::*;
use std::env;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

// Our two keys can not be higher than this value
// This makes cracking the code relatively simple, but frees us
// from having to use BigUint everywhere for multiplication!
const MAX_KEY_VAL: u32 = 65536;

// The different functions supported by the program -
// 1. Generate a keypair
// 2. Sign a message
// 3. Verify a signature against a message
enum Function {
    Generate,
    Sign,
    Verify,
}

// ****************************************************************
// Helper functions
// ****************************************************************


/// Check primality of a given unsigned integer
/// This is a pretty straightforward implementation of the `6k +/- 1` trial
/// division primality test described
/// [here](https://en.wikipedia.org/wiki/Primality_test#Simple_methods).

fn is_prime(n: u32) -> bool {
    if n <= 3 {
        return n > 1;
    } else if n % 2 == 0 || n % 3 == 0 {
        return false;
    }

    let mut i = 5;

    while i * i <= n {
        if n % i == 0 || n % (i + 2) == 0 {
            return false;
        }
        i += 6;
    }
                
    true
        
}

/// This function will return a random prime.
/// It does this by randomly generating an integer and testing if it's
/// prime.  There are definitely more efficient algorithms for this,
/// but this is meant to be as simple as possible.

fn get_random_prime(rng: &mut rand::prelude::ThreadRng) -> u32 {

    // Generate a random 16-bit unsigned integer.
    let mut p: u32; 

    // Keep generating random numbers and putting them in `p` until
    // the generated number is found to be prime.
    // Note that Rust does not have a do...while equivalent, so this
    // break statement may seem strange if you are coming from a different
    // language.
    loop {
        
        p = rng.gen_range(3, MAX_KEY_VAL);

        if is_prime(p) {
            break;
        }

    }

    // Return the last generated number, which should be prime
    p

}

// Check to see if two integers, x and y are coprime.  Numbers are coprime
// if their only common factor is 1.  For example, 4 and 8 are not coprime
// since they both contain 2 as one of their factors; 5 and 8 are coprime
// since they do not share any factors.

fn is_coprime(x: u32, y: u32) -> bool {
    num::integer::gcd(x, y) == 1
}

// A simple implementation of the Carmichael's totient function
fn carmichael_totient(x: u32, y: u32) -> u32 {
    num::integer::lcm(x - 1, y - 1)
}

// Modular multiplicative inverse code based on Rosetta Code's MMI code:
// https://rosettacode.org/wiki/Modular_inverse#Rust

fn mmi(a_unsigned: u32, m_unsigned: u32) -> u32 {

    // Generally, we have been using unsigned integers but we
    // need signed for this algorithm.
    let a: i64 = a_unsigned as i64;
    let m: i64 = m_unsigned as i64;
    
    let mut mn = (m, a);
    let mut xy = (0, 1);
    
    while mn.1 != 0 {
        xy = (xy.1, xy.0 - (mn.0 / mn.1) * xy.1);
        mn = (mn.1, mn.0 % mn.1);
    }
    
    while xy.0 < 0 {
        xy.0 += m;
    }

    if xy.0 > 0 {
        xy.0 as u32
    } else {
        // This should not happen - if it does, there's a bug in my code
        panic!("Received negative inverse");
    }
}

// Given any object, return its 32-bit hash.  A hash is simply a fixed
// size representation of an arbitrary amount of data.  For example,
// a simple hash function might be to take all of the letters of a string,
// add up their ASCII values, and return the result modulo 10.  No matter
// what the size of the input, the ouput will always be one digit (0 - 9).
// Another exercise in this course will delve deeply into hash functions.

fn get_hash<T: Hash>(t: &T) -> u32 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    let r = s.finish();
    r as u32
}

// A helper function which might be useful for testing your key pair
// generation - if `(d * e) % n == 1` does not hold, the key pair is
// not valid.
// The function attribute `#[allow(dead_code)]` is because under normal
// cirumstances, this code will not be used - it's merely for debugging help.
// But we don't really need a warning about this every time we compile -
// this turns that off.

#[allow(dead_code)]
fn check_vals(d: u32, e: u32, n: u32) {
    let bd = BigUint::from(d);
    let be = BigUint::from(e);
    let bn = BigUint::from(n);
    let one = BigUint::from(1 as u32);
    if (bd * be) % bn != one {
        panic!("Error: (d * e) % n != 1");
    } else {
        println!("all is good");
    }
}

// Raise x to the power of y modulo z and return the result.

fn raise_power_modulo(x: u32, y: u32, z: u32) -> u32 {
    // Internally convert to biguints, simply to take advantage of
    // the built-in modpow() function
    let xb: BigUint = BigUint::from(x);
    let yb: BigUint = BigUint::from(y);
    let zb: BigUint = BigUint::from(z);

    let r  = xb.modpow(&BigUint::from(yb),
                       &BigUint::from(zb));

    r.to_u32().unwrap()

}

/// Simple function to tell the user about appropriate usage and exit with exit code 1.
fn print_usage_and_exit() {
    println!("Usage:");
    println!("generate - generates a public/private keypair");
    println!("sign <msg> <priv_key_mod> <priv_key_exp>- signs a message with private key");
    println!("verify <msg> <signature> <pub_key_mod> <pub_key_exp> - verifies a message");
    std::process::exit(1);
}


/// "Wrapper function" to check that the arguments passed in are
/// valid.  If all arguments are good, call the correct
/// function (Generate, Sign, or Verify).

fn args_good(args: &Vec<String>) -> Result<Function, String> {

    // ignore "0 arg", i.e. the executable name itself.
    // This means that all argument lengths here are "one more" than you
    // might expect, e.g. "./foo bar" is two arguments - "./foo" (program
    // name) and "bar" (actual argument")

    if args.len() < 2 {
        return Err("Not enough arguments".to_string());
    } else if args.len() > 6 {
        return Err("Too many arguments".to_string());
    }

    // A different number of arguments is expected for each of the
    // different functions
    
    match args[1].as_ref() {
        "generate" => {
            if args.len() != 2 {
                Err("generate takes no arguments".to_string())
            } else {
                Ok(Function::Generate)
            }
        },
        "sign" => {
            if args.len() != 5 {
                Err("sign requires three arguments".to_string())
            } else {
                Ok(Function::Sign)
            }

        },
        "verify" => {
            if args.len() != 6 {
                Err("verify requires four arguments".to_string())
            } else {
                Ok(Function::Verify)
            }

        },
        _ => {
            Err("Unrecognized first argument".to_string())
        },
    }

}

// Simple helper function to print out a keypair

fn print_keys(n: u32, d: u32, e: u32) {
    println!("Private key: {}, {}", n, d);
    println!("Public key: {}, {}", n, e);
}


// ****************************************************************
// WORK STARTS HERE
// ****************************************************************

// Given a random number generator, produce two distinct pseudorandom primes.

fn generate_two_primes(mut rng: &mut rand::prelude::ThreadRng) -> (u32, u32) {

    // TODO 1
    
    let mut p;
    let mut q;

    // Generally this loop should not execute more than once, but on the
    // off chance that we generate the same prime twice, we loop until
    // they are distinct.
    loop {

        // Step 1: Generate two random primes for p and q
        //         Hint: the get_random_prime() function might be useful
        
        p = get_random_prime(&mut rng);
        q = get_random_prime(&mut rng);

        // Step 2: Break out of the loop if p and q are distinct (i.e.
        //         not the same)
        if p != q {
            break;
        }
    }

    // Step 3: Return p and q as a tuple
    (p, q)
}



// We need to pick a private exponent which is greater than 1 and less than
// c, and is coprime with c.  This can be pseudorandomly generated via the
// random number generator, rng, passed in via argumemt.

fn choose_private_exponent(c: u32, rng: &mut rand::prelude::ThreadRng) -> u32 {

    // TODO 2
    
    let mut p;
    
    loop {
        // Step 1: Generate a random integer betwen 2 and c
        p = rng.gen_range(2, c);
        
        // Step 2: If the generated integer and c are coprime, break
        //         out of the loop
        if is_coprime(p, c) {
            break;
        }
    }

    // Step 3: Return the gen
    p

}

// The public exponent is simply the multiplicative inverse of e modulo n

fn compute_public_exponent(e: u32, n: u32) -> u32 {

    // TODO 3

    // Step 1: Generate and return the multiplicative inverse of e modulo n.
    //         Hint: the mmi() function might be useful here.
    mmi(e, n)
}


// Given a random number generator rng, return a keypair.  This keypair will
// consist of a modulus, a private exponent, and a public exponent.
// Since the modulus is shared between public and private keys, there is no
// no need to send it back twice.

fn generate_key_pair(mut rng: &mut rand::prelude::ThreadRng) -> (u32, u32, u32) {

    // TODO 4
    
    // Step 1: Choose two distinct prime numbers, p and q.
    //         I recommend you work on TODO 1 before this.
    let (p, q) = generate_two_primes(&mut rng);

    // Step 2: Compute m = p * q (will be the modulus)
    let m = p * q;

    // Step 3: Compute n = Carmichael's totient function of p, q
    //         Carmichael's Totient is simply lcm(p - 1, q - 1) - I have
    //         included a helper function, carmichael_totient(), for you.
    let n = carmichael_totient(p, q);
    
    // Step 4: Choose some e which is coprime to n and 1 < e < n
    //         I recommend you work on TODO 2 before this.
    let e = choose_private_exponent(n, &mut rng);
    
    // Step 5: Compute the modular multiplicative inverse for d
    //           I recommend you work on TODO 3 before this.
    let d = compute_public_exponent(e, n);

    // DEBUG: Perform a sanity check before returning.
    //         Verify that d * e = 1 modulo n.
    //         If it does not, panic!
    // If your code works, this is superfluous, but may be useful for
    // testing.  Uncomment the next line to turn this check on.
    // check_vals(d, e, n);
    
    // Return a three-tuple with the following elements:
    // 1. Modulus (m)
    // 2. Private Exponent (e)
    // 3. Public Exponent (d)
    (m, e, d)
}


// Given a message, a private key modulus, and a private key exponent,
// return its signature as a 32-bit unsigned integer.

fn sign_message(msg: String, priv_key_mod: u32, priv_key_exp: u32) -> u32 {
    // TODO 5
    
    // Step 1: Produce a hash value of the message.  Note that I have
    // included a get_hash() function for you to use.  
    let h = get_hash(&msg);
    
    // Step 2: Raise the hash to the power of the private key exponent, modulo the
    // private key modulus (which is, of course, same as the public key modulus).
    // Note that I have included a raise_power_modulo() function.
    let r = raise_power_modulo(h, priv_key_exp, priv_key_mod);

    // Step 3: Return the result of the previous operation
    r
    
}


// Given a message, a signature, a public key modulus, and a public key exponent,
// return true if the signature was signed by the equivalent private key, or
// false if not.

fn verify_signature(msg: String, sig: u32, pub_key_mod: u32, pub_key_exp: u32) -> bool {

    // TODO 6
    
    // Step 1: Get the hash value of the message.
    //         Remember there is a get_hash() function for you to use.
    let h = get_hash(&msg);
        
    // Step 2: Raise the signature to the power of pub_key_exp modulo
    //         pub_key_mod.  Remember there is a raise_power_modulo() function
    //         for you to use.
    let r = raise_power_modulo(sig, pub_key_exp, pub_key_mod);

    // Step 3: Return true if the result of the previous operation is equal to
    // the hash value modulo the public key modulus, false otherwise.
    r == h % pub_key_mod
}

fn main() {

    // Get the arguments from the environment
    
    let mut args = Vec::new();
    for argument in env::args() {
        args.push(argument);
    }

    // Check if the arguments passed in from the command line are good
    let args_ok = args_good(&args);

    // If the arguments were good, perform the correct function
    // Note that there is another way this can fail, if you pass in
    // something that is expected to be an integer but cannot be parsed.
    // This check should also probably be in args_good() but the error
    // is pretty self-explanatory ("Invalid Digit")
    
    // Otherwise, display the error, show usage, and exit
    match args_ok {
        Ok(f) => {
            match f {
                Function::Generate => {
                    let mut rng = rand::thread_rng();
                    let (m, d, e) = generate_key_pair(&mut rng);
                    print_keys(m, d, e);
                },
                Function::Sign => {
                    let msg: String = args[2].clone();
                    let priv_key_mod = args[3].parse::<u32>().unwrap();
                    let priv_key_exp = args[4].parse::<u32>().unwrap();
                    let sig = sign_message(msg, priv_key_mod, priv_key_exp);
                    println!("Signature: {}", sig);
                },
                Function::Verify => {
                    let msg: String = args[2].clone();
                    let sig = args[3].parse::<u32>().unwrap();
                    let pub_key_mod = args[4].parse::<u32>().unwrap();
                    let pub_key_exp = args[5].parse::<u32>().unwrap();

                    let r = verify_signature(msg, sig, pub_key_mod, pub_key_exp);
                    if r {
                        println!("Signature verified!");
                    } else {
                        println!("SIGNATURE INVALID!"); 
                    }

                },
            }
        },
        Err(e) => {
            println!("Error: {}", e);
            print_usage_and_exit();
        },
    }
}

// Tests start here
// Run "cargo test" to run all of them

#[cfg(test)]
mod tests {
    use super::*;

    // ****************************************************************
    // is_prime(n) function
    // ****************************************************************

    
    #[test]
    fn test_5_is_prime() {
        assert!(is_prime(5), "5 should be prime");
    }

    #[test]
    fn test_6_is_not_prime() {
        assert!(!is_prime(6), "6 should not be prime");
    }

    #[test]
    fn test_1000_is_not_prime() {
        assert!(!is_prime(1000), "1000 should not be prime");
    }
    
    #[test]
    fn test_1223_is_prime() {
        assert!(is_prime(1223), "1223 should be prime");
    }

    
    // ****************************************************************
    // get_random_prime() function
    // ****************************************************************

    #[test]
    fn test_gets_random_prime() {
        let mut rng = rand::thread_rng();
        let p = get_random_prime(&mut rng);
        assert!(is_prime(p));
    }

    // ****************************************************************
    // coprimes() function
    // ****************************************************************

    #[test]
    fn test_8_5_are_coprime() {
        assert!(is_coprime(8, 5), "8, 5 should be coprime");
    }

    #[test]
    fn test_8_6_are_not_coprime() {
        assert!(!is_coprime(8, 6), "8, 6 should not be coprime");
    }

    // TODO 1 test


    // Generate 10 times.  At each iteration, the resultant values
    // should both be prime and distinct from each other (i.e. not equal).
    // This is kind of a poor man's stochastic testing. =)
    #[test]
    fn test_generate_two_primes() {
        let mut rng = rand::thread_rng();
        for _ in 0..10 {
            let (p, q) = generate_two_primes(&mut rng);
            assert!(p != q);
            assert!(is_prime(p));
            assert!(is_prime(q));
        }
    }

    // TODO 2 tests

    #[test]
    fn test_choose_private_exponent() {
        let c = 70429;
        let mut rng = rand::thread_rng();
        for _ in 0..10 {
            let p = choose_private_exponent(c, &mut rng);
            assert!(is_coprime(p, c));
            assert!(p > 1);
            assert!(p < c);

        }

    }

    // TODO 3 tests
    // fn compute_public_exponent(e: u32, n: u32) -> u32 {

    #[test]
    fn test_compute_public_exponent_1() {
        let e: u32 = 600010331;
        let n: u32 = 654955584;
        let r = compute_public_exponent(e, n);
        assert!(r == 4070099);
    }

    #[test]
    fn test_compute_public_exponent_big() {
        let e: u32 = 54741371;
        let n: u32 = 314700540;
        let r = compute_public_exponent(e, n);
        assert!(r == 151583711);
    }

    // TODO 4 tests

    #[test]
    fn test_generate_key_pair_hash_500() {
        let h = 500;
        let mut rng = rand::thread_rng();
        for _ in 0..10 {
            let (m, e, d) = generate_key_pair(&mut rng);
            let r1 = raise_power_modulo(h, d, m);
            let r2 = raise_power_modulo(r1, e, m);
            assert!(r2 == h % m);
        }

    }

    #[test]
    fn test_generate_key_pair_hash_99999999() {
        let h = 99999999;
        let mut rng = rand::thread_rng();
        for _ in 0..10 {
            let (m, e, d) = generate_key_pair(&mut rng);
            let r1 = raise_power_modulo(h, d, m);
            let r2 = raise_power_modulo(r1, e, m);
            assert!(r2 == h % m);
        }

    }
    
    // TODO 5 tests

    #[test]
    fn test_sign_message_foo() {
        let msg: String = "foo".to_string();
        let sig = sign_message(msg, 262373123, 120571543);
        assert!(sig == 111862601);
    }

    #[test]
    fn test_sign_message_bar() {
        let msg: String = "bar".to_string();
        let sig = sign_message(msg, 3360057163, 423721031);
        assert!(sig == 2318946848);
    }

    #[test]
    fn test_sign_message_meow() {
        let msg: String = "meow".to_string();
        let sig = sign_message(msg, 1240214083, 97643729);
        assert!(sig == 866459596);
    }

    
    // TODO 6 tests

    // This signature is correct
    #[test]
    fn test_verify_signature_dog_correct() {
        assert!(verify_signature("dog".to_string(),
                               11318728,
                               4228098967,
                               26379711));
    }

    // This signature is incorrect
    #[test]
    fn test_verify_signature_dog_incorrect() {
        assert!(!verify_signature("dog".to_string(),
                               0,
                               4228098967,
                               26379711));
    }
    
}


