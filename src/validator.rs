use crate::token::CheckParameters;

use super::matcher::SqlMatcher;
use super::token::SqlToken;

/*
pub struct QueryInfo<T: SqlToken> {
    fwd_tokens: Vec<(T, usize)>,
    rev_tokens: Option<Vec<(T, usize)>>,
}

impl<T: SqlToken> QueryInfo<T> {
    pub fn new(query: &str, matcher: &SqlMatcher<T>) -> Self {
        let tokens = T::scan_forward(query);

        QueryInfo {
            fwd_tokens: tokens,
            rev_tokens: None,
        }
    }

    pub fn forward_tokens(&self) -> &Vec<(T, usize)> {
        self.fwd_tokens.as_ref()
    }

    pub fn reverse_tokens(&self) -> &Vec<(T, usize)> {
        match self.rev_tokens {
            Some(tokens) => tokens.as_ref(),
            None => {
                self.rev_tokens.insert(T::scan_reverse(query))
            }
        }
    }

    /*
    pub fn is_exact_match(&self) -> bool {
        match self.prefix {
            Some((id, index)) => index == (self.fwd_tokens.len() - 1),
            None => false,
        }
    }
    */


}
*/

pub struct SqlValidator<T: SqlToken> {
    matcher: SqlMatcher<T>,
    params: CheckParameters,
}

// TODO: should there just be `check_query()` with a closure passed in?
impl<T: SqlToken> SqlValidator<T> {
    pub fn new(check_parameters: CheckParameters) -> Self {
        SqlValidator {
            matcher: SqlMatcher::new(),
            params: check_parameters,
        }
    }

    // Ok(s) => go ahead and send the query through to the SQL server
    // Err(s) => send the following error back through to the client
    pub fn check_query(&mut self, query: &str) -> Result<(), &'static str> {
        let tokens = T::scan_forward(query);

        println!("Tokenized query into: {:?}", &tokens);

        let prefix = self.matcher.match_prefix(tokens.as_ref());

        if let Some(prefix_info) = prefix {
            // First, accept queries that have been seen before (even if a parameter is later detected to be vulnerable)
            if prefix_info.is_exact_match {
                return Ok(());
            }

            // Then immediately reject queries that haven't been seen, but have a vulnerable parameter
            if prefix_info.has_vuln_prefix {
                return Err("vulnerable prefix detected for new query");
            }

            // And if neither of these cases fit, do another O(n) scan on the query to get suffix information
            let reverse_tokens = T::scan_reverse(query);
            let suffix = self.matcher.match_suffix(&reverse_tokens, &prefix_info);

            // TODO: all of the control flow paths below check the entire SQL query. We could just check whatever is between the prefix & suffix...
            // Won't do for now, since it's O(n) as it stands

            // Advance up to last token of prefix (e.g. the opening `'` in a parameter if it lies within apostraphes)
            let token_iter = tokens[prefix_info.directional_index..].iter();

            // 2a. If prefix + suffix, do full check of malicious queries
            // 2b. If prefix only, do subset of checks
            // 2c. If nothing, do subset of checks (or no checks)
            match suffix {
                // Prefix and suffix match: could likely be SQL injection on query we've already seen, but could also be a new query pattern
               Some(suffix_info) => {
                    let mut middle_cnt = tokens.len() - prefix_info.directional_index;
                    for (cnt, (_, abs_idx)) in token_iter.clone().enumerate() {
                        if *abs_idx > suffix_info.absolute_index {
                            middle_cnt = cnt;
                            break
                        }
                    }

                    if T::is_malicious_query(token_iter.take(middle_cnt).map(|(t, _)| t), &self.params) {
                        self.matcher.mark_vuln(&tokens, Some(prefix_info.get_id()));
                        return Err("query matched a malicious pattern");
                    }
                }
                // Prefix matches, no suffix found: either null byte injection, or pattern hasn't been seen before but happens to match some other prefix
                None => {
                    if T::is_malicious_query(tokens.iter().map(|(t, _)| t), &self.params) {
                        self.matcher.mark_vuln(&tokens, Some(prefix_info.get_id()));
                        return Err("query matched a malicious pattern");
                    }
                }
            }
        } else if T::is_malicious_query(tokens.iter().map(|(t, _)| t), &self.params) {
            // No prefix or suffix matches--query pattern has never been seen before
            self.matcher.mark_vuln(&tokens, None);
            return Err("query matched a malicious pattern");
        }

        // Now send data to the server and receive either a response or a SQL error.
        Ok(())
    }

    pub fn update_good_query(&mut self, query: &str) {
        let tokens = T::scan_forward(query); // TODO: could pass around ValidationData to these for fewer scanning passes if needs be...
        self.matcher.update_pattern(tokens); // Adds new safe pattern to matcher
    }

    // SQL Errors should come here
    pub fn update_bad_query(&mut self, query: &str) {
        let tokens = T::scan_forward(query);

        let prefix_id = match self.matcher.match_prefix(&tokens) {
            Some(prefix) => {
                if prefix.is_exact_match {
                    return // If a query has previously been whitelisted, we don't want to blacklist it just because it returned a SQL error...
                }

                Some(prefix.get_id())
            }
            None => None,
        };

        self.matcher.mark_vuln(&tokens, prefix_id);
    }
}
