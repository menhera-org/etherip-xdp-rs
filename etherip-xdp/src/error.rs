
use std::fmt::Display;

use portable_string::PortableString;

#[derive(Debug, Clone, Copy)]
pub struct EtheripError {
    msg: PortableString<256>,
}

impl EtheripError {
    pub fn new(msg: &str) -> Self {
        Self {
            msg: PortableString::new_until_null(msg)
        }
    }
}

impl Display for EtheripError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EtheripError: {}", self.msg)
    }
}

impl std::error::Error for EtheripError {}
