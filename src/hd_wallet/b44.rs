use crate::Result;
use crate::errors::WalletBipError;
use crate::hd_wallet::{Client, ExtendedPubPrivKey};
use bip32::{ChildNumber, XPrv};
use eyre::eyre;
use std::str::FromStr;

pub trait Bip44: Client {
    const ROOT_KEY_DEPTH: u8 = 0;

    fn prepare_account_extended_key(
        root_key: &str,
        coin: Coin,
        account: u32,
    ) -> Result<ExtendedPubPrivKey>;

    fn prepare_extended_key(account_key: &str, is_external: bool) -> Result<ExtendedPubPrivKey>;
}

#[derive(Debug, Hash, PartialEq, Eq)]
pub enum Coin {
    Btc,
    Eth,
}

impl From<Coin> for u32 {
    fn from(coin: Coin) -> u32 {
        match coin {
            Coin::Btc => 0,
            Coin::Eth => 60,
        }
    }
}

pub struct BlockExplorer;

impl Client for BlockExplorer {
    const EXTENDED_KEY_DEPTH: u8 = 4;

    const IS_HARDENED_ADDRESSES: bool = false;
}
impl Bip44 for BlockExplorer {
    fn prepare_account_extended_key(
        root_key: &str,
        coin: Coin,
        account: u32,
    ) -> Result<ExtendedPubPrivKey> {
        let root = XPrv::from_str(root_key)?;

        if root.attrs().depth != Self::ROOT_KEY_DEPTH {
            return Err(WalletBipError::Unexpected(eyre!(
                "Key depth must be {}",
                Self::ROOT_KEY_DEPTH
            )));
        }

        // m/44'/coin'/account'
        let privkey = root
            .derive_child(ChildNumber::new(44, true)?)?
            .derive_child(ChildNumber::new(coin as u32, true)?)?
            .derive_child(ChildNumber::new(account, true)?)?;
        let pubkey = privkey.public_key();

        Ok(ExtendedPubPrivKey::new(&pubkey, &privkey))
    }

    fn prepare_extended_key(account_key: &str, is_external: bool) -> Result<ExtendedPubPrivKey> {
        let account_extended = XPrv::from_str(account_key)?;

        // m/44'/coin'/account'/is_external
        let privkey =
            account_extended.derive_child(ChildNumber::new(u32::from(is_external), false)?)?;
        let pubkey = privkey.public_key();

        Ok(ExtendedPubPrivKey::new(&pubkey, &privkey))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod block_explorer {
        use super::*;
        use rstest::rstest;

        #[test]
        fn test_prepare_account_key() {
            let root = "xprv9s21ZrQH143K44CCrMd3EPxUjKWWQkxGYk94ELXf1Jd7x9rhWi2AovprbPJXZ1Pwgyk1Jr37b2Ca3rPyJQyFSnYs296fPHEnccQ8Rc9AKLz";

            let account_extended =
                BlockExplorer::prepare_account_extended_key(root, Coin::Btc, 0).unwrap();

            assert_eq!(
                account_extended.privkey,
                "xprv9zPECzuhYNLzQzEw3kacYkJyAcox4RCKLTYKyB59YpCrPdG3i9TQ5Tzm78LmpheejAPKy1JBKgDqSvouiqrirfVxVXoKhdmi5mVMEWGFr6S"
            );
            assert_eq!(
                account_extended.pubkey,
                "xpub6DNacWSbNjuHdUKQ9n7cutFhieeSTsvAhgTvmZUm79jqGRbCFgmedGKExRZHEfSzzCdxRTkXTGr34oRWruVGS8ie12imQJ4dhVCQAHWFstY"
            );
        }

        #[test]
        fn test_prepare_extended_key() {
            let account_extended = "xprv9zPECzuhYNLzQzEw3kacYkJyAcox4RCKLTYKyB59YpCrPdG3i9TQ5Tzm78LmpheejAPKy1JBKgDqSvouiqrirfVxVXoKhdmi5mVMEWGFr6S";

            let extended = BlockExplorer::prepare_extended_key(account_extended, false).unwrap();

            assert_eq!(
                extended.privkey,
                "xprvA1Nd3YgbqxvrcjZsCA96KsyPrLMK4TbPQq983aiN4k9Sx3DM5aKBnY7ejaasiCcqEwSbLP7QFnDJr2qxcjKhr6fPzQUGrGTS42T5QfQK9tL"
            );
            assert_eq!(
                extended.pubkey,
                "xpub6EMyT4DVgLV9qDeLJBg6h1v8QNBoTvKEn44iqy7yd5gRpqYVd7dSLLS8as4AW1Hz1JntmK1UtRihCejx2JJq81N1nbS1aUGmPcDGjKpt7ss"
            );
        }

        #[rstest]
        #[case(
            0,
            "1P9Qj7dj8kKoZeiHNnG1DLa5rhCbuASSER",
            "023113b0ad2ba91adfa39e5c9e62afa6c0af70618e497c634636d2b521dfae77a5",
            "L4Nzu8iykapKck5UvNqCxWqaEPzTMnRGLBKj3MKLCdtEod5oT36j"
        )]
        #[case(
            7,
            "1KwXtpsAhApw9Dr6hsqAeHS12TYXtLf1cA",
            "02cee2f68d385d983cde284c0f74c02d93d48f41247c1959065cb9a54c7f229bef",
            "L4C3YCrKFWjMAxCV2hTomJBHmkm8C5ZxucjN3aC1MBVjyAT4Bd8a"
        )]
        #[case(
            18,
            "16Ru5NxVjytFf1K17R4vvVJr3zECMp1AER",
            "03e1e79ffaa4c9e5cf897a2a241924ae8f9dc16cc15aecd45c0d7c60514be882f8",
            "KxBXtw8mMcdfLXzmY7BPmJ7WG2oJCNrNwHMumS3QnRnVKww5a6JQ"
        )]
        fn test_prepare_addresses(
            #[case] index: u32,
            #[case] hash: &str,
            #[case] pubkey: &str,
            #[case] privkey: &str,
        ) {
            let extended = "xprvA1Nd3YgbqxvrcjZsCA96KsyPrLMK4TbPQq983aiN4k9Sx3DM5aKBnY7ejaasiCcqEwSbLP7QFnDJr2qxcjKhr6fPzQUGrGTS42T5QfQK9tL";

            let result = BlockExplorer::prepare_address(extended, index).unwrap();

            assert_eq!(result.hash, hash);
            assert_eq!(result.pubkey, pubkey);
            assert_eq!(result.privkey, privkey);
        }
    }
}
