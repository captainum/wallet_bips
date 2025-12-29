use crate::Result;
use crate::errors::WalletBipError;
use crate::hd_wallet::{Client, ExtendedPubPrivKey};
use bip32::{ChildNumber, XPrv};
use core::str::FromStr;
use eyre::eyre;

pub trait Bip32: Client {
    const ROOT_KEY_DEPTH: u8 = 0;

    fn prepare_extended_key(root_key: &str) -> Result<ExtendedPubPrivKey>;
}

struct BitcoinCore;

impl Client for BitcoinCore {
    const EXTENDED_KEY_DEPTH: u8 = 2;

    const IS_HARDENED_ADDRESSES: bool = true;
}

impl Bip32 for BitcoinCore {
    fn prepare_extended_key(root_key: &str) -> Result<ExtendedPubPrivKey> {
        let root = XPrv::from_str(root_key)?;

        if root.attrs().depth != Self::ROOT_KEY_DEPTH {
            return Err(WalletBipError::Unexpected(eyre!(
                "Key depth must be {}",
                Self::ROOT_KEY_DEPTH
            )));
        }

        // m/0'/0'
        let privkey = root
            .derive_child(ChildNumber::new(0, true)?)?
            .derive_child(ChildNumber::new(0, true)?)?;
        let pubkey = privkey.public_key();

        Ok(ExtendedPubPrivKey::new(&pubkey, &privkey))
    }
}

struct Multibit;

impl Client for Multibit {
    const EXTENDED_KEY_DEPTH: u8 = 2;

    const IS_HARDENED_ADDRESSES: bool = false;
}

impl Bip32 for Multibit {
    fn prepare_extended_key(root_key: &str) -> Result<ExtendedPubPrivKey> {
        let root = XPrv::from_str(root_key)?;

        if root.attrs().depth != Self::ROOT_KEY_DEPTH {
            return Err(WalletBipError::Unexpected(eyre!(
                "Key depth must be {}",
                Self::ROOT_KEY_DEPTH
            )));
        }

        // m/0'/0
        let privkey = root
            .derive_child(ChildNumber::new(0, true)?)?
            .derive_child(ChildNumber::new(0, false)?)?;
        let pubkey = privkey.public_key();

        Ok(ExtendedPubPrivKey::new(&pubkey, &privkey))
    }
}
struct BlockExplorer;

impl Client for BlockExplorer {
    const EXTENDED_KEY_DEPTH: u8 = 3;

    const IS_HARDENED_ADDRESSES: bool = false;
}

impl Bip32 for BlockExplorer {
    fn prepare_extended_key(root_key: &str) -> Result<ExtendedPubPrivKey> {
        let root = XPrv::from_str(root_key)?;

        if root.attrs().depth != Self::ROOT_KEY_DEPTH {
            return Err(WalletBipError::Unexpected(eyre!(
                "Key depth must be {}",
                Self::ROOT_KEY_DEPTH
            )));
        }

        // m/44'/0'/0'
        let privkey = root
            .derive_child(ChildNumber::new(44, true)?)?
            .derive_child(ChildNumber::new(0, true)?)?
            .derive_child(ChildNumber::new(0, true)?)?;
        let pubkey = privkey.public_key();

        Ok(ExtendedPubPrivKey::new(&pubkey, &privkey))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    mod bitcoin_core {
        use super::*;

        #[test]
        fn test_prepare_extended_key() {
            let root = "xprv9s21ZrQH143K44CCrMd3EPxUjKWWQkxGYk94ELXf1Jd7x9rhWi2AovprbPJXZ1Pwgyk1Jr37b2Ca3rPyJQyFSnYs296fPHEnccQ8Rc9AKLz";

            let extended = BitcoinCore::prepare_extended_key(root).unwrap();

            assert_eq!(
                extended.privkey,
                "xprv9wfndKaiDKD8UKCVyYhDG5boquxEqEZD2Dr2CNxNDKLtZw3tqvJZ1DgFyqWqa2DPwSoApgDy7BdrG8YaxbHTdGMWMP5X2n957iBYPAfDKKy"
            );
            assert_eq!(
                extended.pubkey,
                "xpub6Af92q7c3gmRgoGy5aEDdDYYPwnjEhH4PSmczmMymessSjP3PTcoZ1zjq75AXGHTaRU7WMYWsw1Cdc1u5knfzChi8FJxv6ipPgPbbds27ns"
            );
        }

        #[rstest]
        #[case(
            0,
            "1J5Wkr98QQzjxihS274XRaS5vvzoEKfS8Z",
            "03f9aa5ce4807a7fe838b17db9c3225a98f94d56bc3ff9f573ed1ca9ea413ddd68",
            "KxqYqoHKp62J7QBXkwVDvyhWKW19FJg7P8nLdvR3z1PiVNdDPKA1"
        )]
        #[case(
            7,
            "1LLqGgj2sJxBF2UhYvoD2ujMvQxaaSm7eC",
            "02c415a740d44170d5d5d9c17bd51281503c8553752a829a78f80202a64ebf0cc2",
            "L3pGtk9GTSicncxkkuMdejsVNTiWCnCdUVXByY4HKUoKh2nhyShq"
        )]
        #[case(
            18,
            "1NzzekNeBPAezB1VfBRXgrM4Zi6z14nDSk",
            "0261ed52201537be9795c6aeb654bad647c70b4bab055149cb2e34196d2d7c399a",
            "L5YJ7ejvJBpmK8humYtLvZoh6qCc9SgyH9SqMxefcc5oVGGbJAEd"
        )]
        fn test_prepare_addresses(
            #[case] index: u32,
            #[case] hash: &str,
            #[case] pubkey: &str,
            #[case] privkey: &str,
        ) {
            let extended = "xprv9wfndKaiDKD8UKCVyYhDG5boquxEqEZD2Dr2CNxNDKLtZw3tqvJZ1DgFyqWqa2DPwSoApgDy7BdrG8YaxbHTdGMWMP5X2n957iBYPAfDKKy";

            let result = BitcoinCore::prepare_address(extended, index).unwrap();

            assert_eq!(result.hash, hash);
            assert_eq!(result.pubkey, pubkey);
            assert_eq!(result.privkey, privkey);
        }
    }

    mod multibit {
        use super::*;

        #[test]
        fn test_prepare_extended_key() {
            let root = "xprv9s21ZrQH143K44CCrMd3EPxUjKWWQkxGYk94ELXf1Jd7x9rhWi2AovprbPJXZ1Pwgyk1Jr37b2Ca3rPyJQyFSnYs296fPHEnccQ8Rc9AKLz";

            let extended = Multibit::prepare_extended_key(root).unwrap();

            assert_eq!(
                extended.privkey,
                "xprv9wfndKaZsegAGojErEykgw5Td6nW1qXkbkoVRHCFV2yPv6gNkTbKNpqrLfTXoi8HVVCPLcUNtQaWFao3ecE53qeYRcE5jVBCyCAiXiVW86y"
            );
            assert_eq!(
                extended.pubkey,
                "xpub6Af92q7Ti2ETVHohxGWm452CB8czRJFbxyj6Dfbs3NWNnu1XHzuZvdALBwqA8vjdkyfeDTnj2NDGs48xqfJJDR7zZT5JxUt17qnmmh4Govs"
            );
        }

        #[rstest]
        #[case(
            0,
            "1Kz3Tq4u89vEk2RZN6EF888nsA289C5kMD",
            "03f12ed866c2e892dedea1320a7298ac68c495d68d796b0c981d2225cf4d6ff01b",
            "KyRLATrVEZv4qdipepqvKuFkd5j8nmjRHuNLQJ6E6Hhq2mxhyD6a"
        )]
        #[case(
            7,
            "13GEofuoFC3ATTfhQtuwbR3u1ZBRk4cDA7",
            "03408241ff5d956c80ea7cef3a6b20baa96514572e15bbaef2186e90f8009db77c",
            "KzpanrFiMDDcWGG8jbC7TNEp6EdnrAVEz1R68TAFFPKkteLp2Gne"
        )]
        #[case(
            18,
            "1KBHf6tUkiuxrfETmXduB6He2Dvgw9Ve2j",
            "03613df817c54f4d215433a825dd52dc6e6948131c2401e258d4e5e37a8f9af37e",
            "Kz7bY9vZEJALWVVSBw9x759NT6U3kUDuYAUxQEfrW5T22ugyakNs"
        )]
        fn test_prepare_addresses(
            #[case] index: u32,
            #[case] hash: &str,
            #[case] pubkey: &str,
            #[case] privkey: &str,
        ) {
            let extended = "xprv9wfndKaZsegAGojErEykgw5Td6nW1qXkbkoVRHCFV2yPv6gNkTbKNpqrLfTXoi8HVVCPLcUNtQaWFao3ecE53qeYRcE5jVBCyCAiXiVW86y";

            let result = Multibit::prepare_address(extended, index).unwrap();

            assert_eq!(result.hash, hash);
            assert_eq!(result.pubkey, pubkey);
            assert_eq!(result.privkey, privkey);
        }
    }

    mod block_explorer {
        use super::*;

        #[test]
        fn test_prepare_extended_key() {
            let root = "xprv9s21ZrQH143K44CCrMd3EPxUjKWWQkxGYk94ELXf1Jd7x9rhWi2AovprbPJXZ1Pwgyk1Jr37b2Ca3rPyJQyFSnYs296fPHEnccQ8Rc9AKLz";

            let extended = BlockExplorer::prepare_extended_key(root).unwrap();

            assert_eq!(
                extended.privkey,
                "xprv9zPECzuhYNLzQzEw3kacYkJyAcox4RCKLTYKyB59YpCrPdG3i9TQ5Tzm78LmpheejAPKy1JBKgDqSvouiqrirfVxVXoKhdmi5mVMEWGFr6S"
            );
            assert_eq!(
                extended.pubkey,
                "xpub6DNacWSbNjuHdUKQ9n7cutFhieeSTsvAhgTvmZUm79jqGRbCFgmedGKExRZHEfSzzCdxRTkXTGr34oRWruVGS8ie12imQJ4dhVCQAHWFstY"
            );
        }

        #[rstest]
        #[case(
            0,
            "19ALxgzQrzh1XiujMMF55oyrto8UL3Jeqi",
            "0335e8c271da1c5104122df2674722a57a10c54372630ee111384ad880482a0584",
            "L1FUmh2h4ug8Wt3pHVACE59mNJ7c5fXo57iunSjpqcuzvTeSBrGa"
        )]
        #[case(
            7,
            "1HRirJhkT9Tb3PNPPMZCnbN7zzEeYrJHPv",
            "034ccb3e77ab5012acf310323c4f4075a72f8a45f5ac6c3117b20736d6d79035f6",
            "Kx9RSfHrrTxoyTxsaevbJoP1z1ivAJo7c2NjBD3PM2wqqYBHBWgc"
        )]
        #[case(
            18,
            "19QFfi9RUiiSQk92J5ex19pGNLRHeZWs5Y",
            "033c49bfb5a89692a1dc1568d07efb5b868522a7d011eed078c771a578744fb031",
            "L21ycZvnmcUvKFbdLYybiNoV12fRurweVxuMQwQFzqR6wtGXvCFG"
        )]
        fn test_prepare_addresses(
            #[case] index: u32,
            #[case] hash: &str,
            #[case] pubkey: &str,
            #[case] privkey: &str,
        ) {
            let extended = "xprv9zPECzuhYNLzQzEw3kacYkJyAcox4RCKLTYKyB59YpCrPdG3i9TQ5Tzm78LmpheejAPKy1JBKgDqSvouiqrirfVxVXoKhdmi5mVMEWGFr6S";

            let result = BlockExplorer::prepare_address(extended, index).unwrap();

            assert_eq!(result.hash, hash);
            assert_eq!(result.pubkey, pubkey);
            assert_eq!(result.privkey, privkey);
        }
    }
}
