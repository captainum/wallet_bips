mod address;
mod b32;
mod b44;

use crate::Result;
use crate::errors::WalletBipError;
use address::Address;
use bip32::secp256k1::ecdsa::{SigningKey, VerifyingKey};
use bip32::{ChildNumber, ExtendedPrivateKey, ExtendedPublicKey, Prefix, XPrv};
use bip39::Mnemonic;
use eyre::eyre;
use std::str::FromStr;

pub fn prepare_seed(mnemonic: &[&str], passphrase: &str) -> Result<[u8; 64]> {
    use std::str::FromStr;
    let mnemonic = Mnemonic::from_str(&mnemonic.join(" "))?;

    Ok(mnemonic.to_seed(passphrase))
}

pub fn prepare_root<S: AsRef<[u8]>>(seed: S) -> Result<String> {
    let root = XPrv::new(seed)?;

    Ok(root.to_string(Prefix::XPRV).to_string())
}

pub struct ExtendedPubPrivKey {
    pubkey: String,
    privkey: String,
}

impl ExtendedPubPrivKey {
    pub fn new(
        pubkey: &ExtendedPublicKey<VerifyingKey>,
        privkey: &ExtendedPrivateKey<SigningKey>,
    ) -> Self {
        Self {
            pubkey: pubkey.to_string(Prefix::XPUB).to_string(),
            privkey: privkey.to_string(Prefix::XPRV).to_string(),
        }
    }
}

pub trait Client {
    const EXTENDED_KEY_DEPTH: u8;

    const IS_HARDENED_ADDRESSES: bool;

    fn prepare_address(extended_key: &str, index: u32) -> Result<Address> {
        let extended = XPrv::from_str(extended_key)?;

        if extended.attrs().depth != Self::EXTENDED_KEY_DEPTH {
            return Err(WalletBipError::Unexpected(eyre!(
                "Key depth must be {}",
                Self::EXTENDED_KEY_DEPTH
            )));
        }

        let privkey =
            extended.derive_child(ChildNumber::new(index, Self::IS_HARDENED_ADDRESSES)?)?;
        let pubkey = privkey.public_key();

        Address::new(&pubkey, &privkey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    #[test]
    fn test_prepare_seed() {
        let mnemonic =
            "dragon elbow sheriff outdoor undo brisk aware raw inform correct lake truly"
                .split(' ')
                .collect::<Vec<_>>();

        let seed = prepare_seed(&mnemonic, "").unwrap();

        assert_eq!(
            hex::encode(&seed, false).unwrap(),
            "1c5426d456b59ec7f2831ae9c86b64638c498fc48f269a129236db8461f5adbfce60826beee21d1e8992dd2fc710db83b532483dd375d00641f569a0426d4067"
        );

        assert_eq!(
            prepare_seed(&mnemonic, "pass").unwrap(),
            prepare_seed(&mnemonic, "pass").unwrap()
        );
    }

    #[test]
    fn test_prepare_root_key() {
        let mnemonic =
            "dragon elbow sheriff outdoor undo brisk aware raw inform correct lake truly"
                .split(' ')
                .collect::<Vec<_>>();

        let seed = prepare_seed(&mnemonic, "").unwrap();

        let root = prepare_root(seed).unwrap();

        assert_eq!(
            root,
            "xprv9s21ZrQH143K44CCrMd3EPxUjKWWQkxGYk94ELXf1Jd7x9rhWi2AovprbPJXZ1Pwgyk1Jr37b2Ca3rPyJQyFSnYs296fPHEnccQ8Rc9AKLz"
        );
    }
}
