#![allow(dead_code)]
#![warn(clippy::pedantic)]

mod errors;
mod hd_wallet;
mod hex;
mod mnemonic;

use crate::errors::WalletBipError;

pub type Result<T> = core::result::Result<T, WalletBipError>;
