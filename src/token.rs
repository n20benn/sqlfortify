use std::fmt::{Debug, Display};
use std::hash::Hash;

// Note: this trait is meant to work especially well with Enums
pub trait SqlToken: Eq + Hash + Clone + Debug + Display {
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
