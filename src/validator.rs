use super::matcher::SqlMatcher;
use super::token::SqlToken;

pub struct SqlValidator<T: SqlToken> {
    matcher: SqlMatcher<T>,
}

// TODO: should there just be `check_query()` with a closure passed in?
impl<T: SqlToken> SqlValidator<T> {
    pub fn new() -> Self {
        SqlValidator {
            matcher: SqlMatcher::new(),
        }
    }

    // Ok(s) => go ahead and send the query through to the SQL server
    // Err(s) => send the following error back through to the client
    pub fn check_query(&mut self, query: &str) -> Result<(), &'static str> {
        let tokens = T::scan_from(query);

        println!("Tokenized into: {:?}", &tokens);

        // println!("Created tokens: {:?}", &tokens);

        if self.matcher.is_exact_match(&tokens) {
            //self.matcher.update_pattern(tokens); // Updates is_constant values
            return Ok(()); // Send data to the server, don't care about SQL error vs response
        }

        if self.matcher.has_vuln(&tokens) {
            return Err("Vulnerable prefix detected for new query");
            // We won't even consider a new query pattern if there have been indications that
            // SQL injection has been attempted on a parameter in its prefix
        }

        if T::is_malicious_query(&tokens) {
            let ids = self.matcher.match_prefix_suffix(&tokens); // TODO: move this out of `if` stmt, return tokens in between prefix & suffix here and pass to is_malicious_query()?
            self.matcher.mark_vuln(&tokens, &ids);
            return Err("Query matched a malicious pattern");
        }

        // Now send data to the server and receive either a response or a SQL error.

        Ok(())
    }

    pub fn update_good_query(&mut self, query: &str) {
        let tokens = T::scan_from(query);
        self.matcher.update_pattern(tokens); // Adds new safe pattern in
    }

    // SQL Errors should come here
    pub fn update_bad_query(&mut self, query: &str) {
        let tokens = T::scan_from(query);
        let mut ids = self.matcher.match_prefix_suffix(&tokens);

        if ids.is_empty() {
            ids = self.matcher.match_prefix(&tokens);
        }

        self.matcher.mark_vuln(&tokens, &ids);
    }
}
