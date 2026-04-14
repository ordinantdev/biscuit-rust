/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
use core::fmt::Display;
use std::{
    convert::{TryFrom, TryInto},
    str::FromStr,
};

use crate::error;

#[derive(Debug, Copy, Clone, PartialEq, Hash, Eq)]
pub enum Algorithm {
    Ed25519,
    #[cfg(feature = "p256")]
    Secp256r1,
}

impl Algorithm {
    pub fn values() -> &'static [Self] {
        &[
            Self::Ed25519,
            #[cfg(feature = "p256")]
            Self::Secp256r1,
        ]
    }
}

impl Default for Algorithm {
    fn default() -> Self {
        Self::Ed25519
    }
}

impl Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Algorithm::Ed25519 => write!(f, "ed25519"),
            #[cfg(feature = "p256")]
            Algorithm::Secp256r1 => write!(f, "secp256r1"),
        }
    }
}
impl FromStr for Algorithm {
    type Err = error::Format;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.try_into()
    }
}

impl TryFrom<&str> for Algorithm {
    type Error = error::Format;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "ed25519" => Ok(Algorithm::Ed25519),
            #[cfg(feature = "p256")]
            "secp256r1" => Ok(Algorithm::Secp256r1),
            _ => Err(error::Format::DeserializationError(format!(
                "deserialization error: unexpected key algorithm {}",
                value
            ))),
        }
    }
}

impl From<biscuit_parser::builder::Algorithm> for Algorithm {
    fn from(value: biscuit_parser::builder::Algorithm) -> Algorithm {
        match value {
            biscuit_parser::builder::Algorithm::Ed25519 => Algorithm::Ed25519,
            #[cfg(feature = "p256")]
            biscuit_parser::builder::Algorithm::Secp256r1 => Algorithm::Secp256r1,
        }
    }
}

impl From<Algorithm> for biscuit_parser::builder::Algorithm {
    fn from(value: Algorithm) -> biscuit_parser::builder::Algorithm {
        match value {
            Algorithm::Ed25519 => biscuit_parser::builder::Algorithm::Ed25519,
            #[cfg(feature = "p256")]
            Algorithm::Secp256r1 => biscuit_parser::builder::Algorithm::Secp256r1,
        }
    }
}

impl TryFrom<crate::format::schema::public_key::Algorithm> for Algorithm {
    type Error = error::Format;
    fn try_from(
        value: crate::format::schema::public_key::Algorithm,
    ) -> Result<Algorithm, Self::Error> {
        match value {
            crate::format::schema::public_key::Algorithm::Ed25519 => Ok(Algorithm::Ed25519),
            #[cfg(feature = "p256")]
            crate::format::schema::public_key::Algorithm::Secp256r1 => Ok(Algorithm::Secp256r1),
            #[cfg(not(feature = "p256"))]
            _ => Err(error::Format::DeserializationError(
                "P256 support not enabled".to_string(),
            )),
        }
    }
}

impl From<Algorithm> for crate::format::schema::public_key::Algorithm {
    fn from(value: Algorithm) -> crate::format::schema::public_key::Algorithm {
        match value {
            Algorithm::Ed25519 => crate::format::schema::public_key::Algorithm::Ed25519,
            #[cfg(feature = "p256")]
            Algorithm::Secp256r1 => crate::format::schema::public_key::Algorithm::Secp256r1,
        }
    }
}
