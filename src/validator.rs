use crate::token::SqlToken;

use super::matcher::SqlMatcher;
use super::sqli_detector;

pub struct Parameters {
    pub detector_nopattern: sqli_detector::Parameters,
    pub detector_prefix: sqli_detector::Parameters,
    pub detector_prefix_suffix: sqli_detector::Parameters,
}

impl Parameters {
    pub fn default() -> Self {
        Parameters {
            detector_nopattern: sqli_detector::Parameters::default_nopattern(),
            detector_prefix: sqli_detector::Parameters::default_prefix(),
            detector_prefix_suffix: sqli_detector::Parameters::default_prefix_suffix(),
        }
    }
}

pub struct SqlValidator<D: sqli_detector::Detector> {
    matcher: SqlMatcher<D>,
    params: Parameters,
}

// TODO: should there just be `check_query()` with a closure passed in?
impl<D: sqli_detector::Detector> SqlValidator<D> {
    pub fn new(config_parameters: Parameters) -> Self {
        SqlValidator {
            matcher: SqlMatcher::new(),
            params: config_parameters,
        }
    }

    // Ok(s) => go ahead and send the query through to the SQL server
    // Err(s) => send the following error back through to the client
    pub fn check_query(&mut self, query: &str) -> Result<(), &'static str> {
        let tokens = D::Token::scan_forward(query);

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
            let reverse_tokens = D::Token::scan_reverse(query);
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
                            break;
                        }
                    }

                    if D::is_malicious_query(
                        token_iter.take(middle_cnt).map(|(t, _)| t),
                        &self.params.detector_prefix_suffix,
                    ) {
                        self.matcher.mark_vuln(&tokens, Some(prefix_info.get_id()));
                        return Err("query matched a malicious pattern");
                    }
                }
                // Prefix matches, no suffix found: either null byte injection, or pattern hasn't been seen before but happens to match some other prefix
                None => {
                    if D::is_malicious_query(
                        tokens.iter().map(|(t, _)| t),
                        &self.params.detector_prefix,
                    ) {
                        self.matcher.mark_vuln(&tokens, Some(prefix_info.get_id()));
                        return Err("query matched a malicious pattern");
                    }
                }
            }
        } else if D::is_malicious_query(
            tokens.iter().map(|(t, _)| t),
            &self.params.detector_nopattern,
        ) {
            // No prefix or suffix matches--query pattern has never been seen before
            self.matcher.mark_vuln(&tokens, None);
            return Err("query matched a malicious pattern");
        }

        // Now send data to the server and receive either a response or a SQL error.
        Ok(())
    }

    pub fn update_good_query(&mut self, query: &str) {
        let tokens = D::Token::scan_forward(query); // TODO: could pass around ValidationData to these for fewer scanning passes if needs be...
        self.matcher.update_pattern(tokens); // Adds new safe pattern to matcher
    }

    // SQL Errors should come here
    pub fn update_bad_query(&mut self, query: &str) {
        let tokens = D::Token::scan_forward(query);

        let prefix_id = match self.matcher.match_prefix(&tokens) {
            Some(prefix) => {
                if prefix.is_exact_match {
                    return; // If a query has previously been whitelisted, we don't want to blacklist it just because it returned a SQL error...
                }

                Some(prefix.get_id())
            }
            None => None,
        };

        self.matcher.mark_vuln(&tokens, prefix_id);
    }
}
