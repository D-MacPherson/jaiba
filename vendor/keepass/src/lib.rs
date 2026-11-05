#![doc = include_str!("../README.md")]
#![recursion_limit = "1024"]

mod compression;
pub mod config;
pub(crate) mod crypt;
pub mod db;
pub mod error;
pub(crate) mod format;

mod key;

pub use self::db::Database;

#[cfg(feature = "test-support")]
pub use crate::format::kdbx4::credential_valid_kdbx4_with_inner_stream_id_width;

#[cfg(feature = "challenge_response")]
pub use self::key::ChallengeResponseKey;
pub use self::key::DatabaseKey;
