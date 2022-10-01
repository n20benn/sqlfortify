use super::cockroach_token::*;
use super::sqli_detector::*;
use crate::{sqli_detector::MultipleQueries, token::SqlToken};

pub struct CockroachDetector {}

impl Detector for CockroachDetector {
    type Token = CockroachToken;

    fn is_malicious_query<
        'a,
        I: std::iter::DoubleEndedIterator<Item = &'a CockroachToken> + Clone,
    >(
        mut query_iter: I,
        params: &crate::sqli_detector::Parameters,
    ) -> bool
    where
        Self: 'a,
    {
        let test_iter: Vec<&CockroachToken> = query_iter.clone().collect();
        log::info!(
            "tokens being checked for is_malicious_query: {:?}",
            test_iter
        );

        while let Some(token) = query_iter.next() {
            match token {
                CockroachToken::Symbol(';') => match params.multi_queries {
                    MultipleQueries::DisallowAll => return true,
                    MultipleQueries::DisallowCommit => return true,
                    MultipleQueries::DisallowOnOtherIndications => return true,
                    MultipleQueries::AllowAll => (),
                },
                CockroachToken::LineComment if params.disallow_line_comments => return true,
                CockroachToken::BlockCommentOpen if params.disallow_block_comments => return true,
                CockroachToken::Identifier(i) => {
                    if i == "PG_SLEEP" && params.disallow_time_delays {
                        return true;
                    }
                    // Block metadata tables here
                    // Block file/socket/exec functions here?
                }
                CockroachToken::Keyword(Keyword::Or)
                    if params.tautologies != Tautologies::AllowAll =>
                {
                    if is_tautology(query_iter.clone()) {
                        match params.tautologies {
                            Tautologies::DisallowAll => return true,
                            Tautologies::AllowWhereTrue => return true,
                            Tautologies::DisallowCommon => return true, // TODO: need to fix
                            Tautologies::AllowAll => (),
                        }
                    }
                }
                // TODO: Add Keyword::And here to checks for (negative) tautology immediately following 'AND'?
                CockroachToken::Keyword(Keyword::Union) => {}
                // TODO: add logic to see whether a UNION JOIN is malicious
                _ => (),
            }
        }

        false
    }
}

// TODO: need to refactor this code...
fn is_tautology<'a, I: std::iter::DoubleEndedIterator<Item = &'a CockroachToken>>(iter: I) -> bool
where
    CockroachToken: 'a,
{
    let mut iter = iter
        .skip_while(|token| -> bool { token.is_whitespace() })
        .peekable(); // Ignore whitespace

    // Catches some of the trivial cases that are commonly used
    match iter.next() {
        Some(CockroachToken::Keyword(Keyword::True)) => return true,
        Some(c1 @ CockroachToken::Const(_)) => {
            match (iter.next(), iter.next(), iter.next()) {
                (Some(CockroachToken::Symbol('=')), Some(c2), _) => {
                    if c1.deep_eq(&c2) {
                        return true;
                    } // Covers `OR 1=1`
                }
                (
                    Some(CockroachToken::Symbol('!')),
                    Some(CockroachToken::Symbol('=')),
                    Some(c2),
                )
                | (
                    Some(CockroachToken::Symbol('<')),
                    Some(CockroachToken::Symbol('>')),
                    Some(c2),
                ) => {
                    if c1 == c2 && !c1.deep_eq(&c2) {
                        return true;
                    } // `OR 1!=2`
                }
                (Some(CockroachToken::Keyword(kw)), _, _)
                | (_, Some(CockroachToken::Keyword(kw)), _)
                | (_, _, Some(CockroachToken::Keyword(kw))) => {
                    match iter.peek() {
                        Some(CockroachToken::Symbol('(')) => (),
                        _ => {
                            if !kw.is_reserved() {
                                return false;
                            }
                        }
                    };
                }
                (Some(CockroachToken::Identifier(_)), _, _)
                | (_, Some(CockroachToken::Identifier(_)), _)
                | (_, _, Some(CockroachToken::Identifier(_))) => {
                    match iter.peek() {
                        Some(CockroachToken::Symbol('(')) => (), // Found a function (still not a legitimate variable)
                        _ => return false,
                    }
                }
                _ => (),
            };
        }
        Some(CockroachToken::Keyword(kw)) => {
            match iter.peek() {
                Some(CockroachToken::Symbol('(')) => (),
                _ => {
                    if !kw.is_reserved() {
                        return false;
                    }
                }
            };
        }
        Some(CockroachToken::Identifier(_)) => {
            match iter.peek() {
                Some(CockroachToken::Symbol('(')) => (), // Found a function (still not a legitimate variable)
                _ => return false,
            }
        }
        _ => (),
    };

    // If the entire rest of the query has no more Identifiers, it would
    // mean that the OR expression is based on values that are constant at the
    // time they are passed in (meaning that it would evaluate to always true/always false,
    // rather than conditionally true based on values in a particular column/table).
    // This can catch either a tautology + Null byte injection attack, or else a
    // tautology injection that happens to be at the very end of a query.

    // TODO: BUG: this only works if Keywords are specifically reserved; for instance,
    // the query `SELECT password FROM passwords WHERE user = 'mitch' OR password = '12345'`
    // triggers a false positive, as PASSWORD is technically a Keyword. This can be fixed by
    // Making a Reserved/Nonreserved distinction on keywords of some sort. For now we disable this.

    while let Some(token) = iter.next() {
        match token {
            CockroachToken::Identifier(_) => {
                match iter.peek() {
                    Some(CockroachToken::Symbol('(')) => (), // Found a function (still not a legitimate variable)
                    _ => return false,
                }
            }
            CockroachToken::Keyword(kw) => {
                match iter.peek() {
                    Some(CockroachToken::Symbol('(')) => (), // Found a function (still not a legitimate variable)
                    _ => {
                        if !kw.is_reserved() {
                            return false;
                        }
                    }
                };
            }
            // We can't know whether or not a non-reserved keyword is acutally an identifier, so we treat it as such
            _ => (),
        }
    }
    true
}
// TODO: we could also check tautology when we pattern match--if the pattern doesn't match,
// retrieve a vec of Tokens that the prefix/suffix stopped at. IF there is and OR and IF there
// are no Identifiers after that OR
