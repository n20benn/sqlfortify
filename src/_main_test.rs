// #[feature(nll)] // Enforced breakage with non-lexical lifetimes (going to be a thing soon in Rust)
#![allow(unused)] // TODO: remove once ready to refine code
#![allow(dead_code)]
#![forbid(unsafe_code)]

mod matcher;
mod validator;
mod token;
//mod iso_token;
//mod postgres_token;
mod cockroach_token;

use std::env;
use matcher::*;
use token::SqlToken;
use cockroach_token::{CockroachToken};

// use bimap::BiMap;

fn help() {
    println!("Usage:
sqlguard <string>[, <string>[, ...]]
    Check whether the given strings are SQLI or not.");
}

fn main() {
    let mut args: Vec<String> = env::args().rev().collect();
    args.pop(); // Remove name environment variable


    let mut sql_checker: SqlMatcher<CockroachToken> = SqlMatcher::new();

    match args.len() {
        0 => {
            help();
        },
        _ => {
            while let Some(arg) = args.pop() {
                println!("Checking: {}", arg);

                match check_query(arg, &mut sql_checker) {
                    Ok(_) => println!("String is safe. Proceed."),
                    Err(reason) => println!("String blocked: {}", reason)
                }
            }
        }
    }
}



// Ok(s) => go ahead and send the query through to the SQL server
// Err(s) => send the following error back through to the client
fn check_query<T: SqlToken>(query: String, matcher: &mut SqlMatcher<T>) -> Result<String,String> { 
    let tokens = T::scan_from(query.as_str());

    println!("Tokenized into: {:?}", &tokens);

    // println!("Created tokens: {:?}", &tokens);

    if matcher.is_exact_match(&tokens) {
        matcher.update_pattern(tokens); // Updates is_constant values
        return Ok(query)
    }

    if matcher.has_vuln(&tokens) { 
        return Err(String::from("Vulnerable prefix detected for new query"))
        // We won't even consider a new query pattern if there have been indications that 
        // SQL injection has been attempted on a parameter in its prefix
    }

    let ids = matcher.match_prefix_suffix(&tokens); // TODO: return tokens in between prefix & suffix here and pass to is_malicious_query()?

    if T::is_malicious_query(&tokens) {
        matcher.mark_vuln(&tokens, &ids);
        return Err(String::from("Query matched a malicious pattern"))
    }

    matcher.update_pattern(tokens); // Adds new safe pattern in
    Ok(query)
}