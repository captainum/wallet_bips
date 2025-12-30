#![allow(dead_code)]
#![warn(clippy::pedantic)]

pub mod errors;
pub mod hd_wallet;

pub mod mnemonic;

mod hex;

use crate::errors::WalletBipError;

pub type Result<T> = core::result::Result<T, WalletBipError>;
