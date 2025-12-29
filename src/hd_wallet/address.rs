use crate::hex;
use bip32::secp256k1::ecdsa::{SigningKey, VerifyingKey};
use bip32::{ExtendedPrivateKey, ExtendedPublicKey};

pub struct Address {
    pub(crate) hash: String,
    pub(crate) pubkey: String,
    pub(crate) privkey: String,
}

impl Address {
    pub fn new(
        pubkey: &ExtendedPublicKey<VerifyingKey>,
        privkey: &ExtendedPrivateKey<SigningKey>,
    ) -> crate::Result<Self> {
        let wif = |privkey: &[u8; 32]| {
            use sha2::{Digest, Sha256};

            let mut payload = [0u8; 34];
            payload[0] = 0x80;
            payload[1..33].copy_from_slice(privkey);
            payload[33] = 0x01;

            let checksum = &Sha256::digest(Sha256::digest(payload))[..4];

            let mut result = [0u8; 38];

            result[..34].copy_from_slice(&payload);
            result[34..].copy_from_slice(checksum);

            bs58::encode(result).into_string()
        };

        let p2pkh = |pubkey: &[u8; 33]| {
            use ripemd::Ripemd160;
            use sha2::{Digest, Sha256};

            let mut payload = [0u8; 21];
            payload[0] = 0x00;
            payload[1..].copy_from_slice(&Ripemd160::digest(Sha256::digest(pubkey))[..20]);

            let checksum = &Sha256::digest(Sha256::digest(payload))[..4];

            let mut result = [0u8; 25];

            result[..21].copy_from_slice(&payload);
            result[21..].copy_from_slice(checksum);

            bs58::encode(result).into_string()
        };

        let hash = p2pkh(&pubkey.to_bytes());
        let privkey = wif(&privkey.to_bytes());
        let pubkey = hex::encode(&pubkey.to_bytes(), false)?;

        Ok(Self {
            hash,
            pubkey,
            privkey,
        })
    }
}
