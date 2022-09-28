use super::token::SqlToken;

#[derive(PartialEq, Eq, Hash, Clone)]
pub enum IsoSqlToken {
    Test,
}

impl SqlToken for IsoToken {
    fn deep_eq(&self, other: &Self) -> bool {
        false // TODO: stub
    }

    fn is_param_token(&self) -> bool {
        false // TODO: stub
    }

    fn scan_from(query: &str) -> Vec<Self> {
        vec![] // TODO: stub
    }

    fn is_malicious_query(pattern: &Vec<Self>) -> bool {
        false
    }
}
