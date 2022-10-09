pub mod cockroach_detector;

mod cockroach_token;
//mod postgres_token;

use std::fmt::{Debug, Display};
use std::hash::Hash;

// Note: this trait is meant to work especially well with Enums
pub trait Token: Eq + Hash + Clone + Debug + Display {
    // Trait Eq should evaluate true if two tokens are the same type.
    // Make sure Hash is implemented so that k1 == k2 -> hash(k1) == hash(k2)
    // deep_eq should evaluate true if two tokens have the same contents.
    // deep_eq must be reflexive, symmetric and transitive (like Eq)
    fn deep_eq(&self, other: &Self) -> bool;

    // Example: two Integer(value) tokens would be Eq as they are
    // both Integer types, but they would only be deep_eq if the value
    // of those types matched exactly too.

    // The reason we do this is so that we can detect whether a value with
    // a user-inputtable type (such as an integer or string) is really
    // manipulated by the user or if it is always constant. For instance:
    // SELECT password FROM passwords WHERE user = 'jake';
    // 'jake' would be scanned to become a String('jake') enum type. The next call:
    // SELECT password FROM password WHERE user = 'lisa';
    // would become a String('lisa') enum type. When compared,
    // String('jake') == String('lisa') under Eq rules so they would be hashed
    // into the same bucket in the hash tree, but String('Jake').deep_eq(String('lisa'))
    // would evaluate to false, thus giving us the information we need to declare the
    // node to be a user-modifiable parameter.

    /// This MUST only be true for one token type. In other words, (t1.is_param_token() && t2.is_param_token()) => (t1 == t2)--though t1 doesn't have to deep_eq() t2.
    fn is_param_token(&self) -> bool;

    fn is_whitespace(&self) -> bool;

    // fn param_tokens() -> Vec<Self>;

    // Since we pass the parameterized type T:SqlToken everywhere,
    // we'll have access to static functions that we desire.
    // It makes better sense to have all scanning/parsing code that
    // is specific to a given token within the token's file (or else
    // referenced directly by the token's file).
    fn scan_forward(query: &str) -> Vec<(Self, usize)>;
    // TODO: you NEED to consolidate anything found in comments into a single token.
    // The reason for this is that comments could appear to be malicious SQL when they are in fact benign.
    // After all, an attacker would have no reason or benefit to inserting SQL comments containing malicious commands...

    fn scan_reverse(query: &str) -> Vec<(Self, usize)>;
}

pub trait Detector {
    type Token: Token;

    fn is_malicious_query<'a, I: std::iter::DoubleEndedIterator<Item = &'a Self::Token> + Clone>(
        query_iter: I,
        params: &Parameters,
    ) -> bool
    where
        Self::Token: 'a;
}

pub struct Parameters {
    /// Any detected block comments (commonly `/*` followed by `*/`)
    pub disallow_block_comments: bool,
    /// Any detected line comments (commonly `--`)
    pub disallow_line_comments: bool,
    /// Any detected commands that intentionally pause the query (e.g. pg_sleep(time) for PostgreSQL)
    pub disallow_time_delays: bool,
    /// Queries containing more than one SQL statement, i.e. those broken up by one or more semicolons
    pub multi_queries: MultipleQueries,
    /// Queries containing statements that always evaluate to true
    pub tautologies: Tautologies,
}

impl Parameters {
    /// Default SQLI detection parameters for queries that matched prefix & suffix
    pub fn default_prefix_suffix() -> Self {
        Parameters {
            disallow_line_comments: true,
            disallow_block_comments: true,
            disallow_time_delays: true,
            multi_queries: MultipleQueries::DisallowAll, // TODO: should we set this to DisallowOnOtherIndications?
            tautologies: Tautologies::DisallowAll,
        }
    }

    /// Default SQLI detection parameters for queries that matched prefix only
    pub fn default_prefix() -> Self {
        Parameters {
            disallow_line_comments: false, // The threat model here is that the attacker is using a null byte injection, which replaces the use of a line comment...
            disallow_block_comments: true,
            disallow_time_delays: true,
            multi_queries: MultipleQueries::DisallowCommit,
            tautologies: Tautologies::DisallowCommon,
        }
    }

    /// Default SQLI detection parameters for queries that matched neither prefix nor suffix
    pub fn default_nopattern() -> Self {
        Parameters {
            disallow_line_comments: false,
            disallow_block_comments: false,
            disallow_time_delays: false,
            multi_queries: MultipleQueries::AllowAll,
            tautologies: Tautologies::AllowAll,
        }
    }
}

#[allow(dead_code)]
pub enum MultipleQueries {
    /// Any instance of multiple SQL queries in one request (i.e. semicolons) are considered malicious
    DisallowAll,
    /// Any semicolons are considered malicious if paired with any other indicator of SQL injection--BEGIN/COMMIT block within query, tautology, metadata table access, etc.
    ///
    /// Note that this includes malicious patterns that would be otherwise disabled per the configuration.
    /// For instance, if Tautologies::AllowAll were set with MultipleQueries::DisallowOnOtherIndications, then the presence of a tautology and a semicolon would be considered malicious and test positive.
    DisallowOnOtherIndications,
    /// If there are any COMMIT commands along with the semicolon, consider it to be malicious
    DisallowCommit,
    /// Don't consider semicolon use to be malicious
    AllowAll,
}

// TODO: update code to check for cases in addition to just following `OR`
#[allow(dead_code)]
#[derive(PartialEq, Eq)]
pub enum Tautologies {
    /// Any detected instance of 'OR' followed by a tautology (a statement that always evaluates to `true`) is considered malicious
    DisallowAll,
    /// All tautologies are considered except for instances of `... WHERE true...`
    AllowWhereTrue,
    /// Searches for commonly-used tautologies, such as `OR true`, `OR '1'='1'`, etc. Most of these come from well-used tools like SQLMap
    DisallowCommon,
    /// Doesn't consider tautologies to be malicious
    AllowAll,
}
