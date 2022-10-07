use super::token::SqlToken;

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

pub trait Detector {
    type Token: SqlToken;

    fn is_malicious_query<'a, I: std::iter::DoubleEndedIterator<Item = &'a Self::Token> + Clone>(
        query_iter: I,
        params: &Parameters,
    ) -> bool
    where
        Self::Token: 'a;
}
