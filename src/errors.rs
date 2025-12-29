use thiserror::Error;

#[derive(Error, Debug)]
pub enum WalletBipError {
    #[error(transparent)]
    GenerateMnemonic(#[from] bip39::Error),

    #[error("Could not split mnemonic: {0}")]
    SplitMnemonic(String),

    #[error(transparent)]
    Crypto(#[from] bip32::Error),

    #[error(transparent)]
    WriteOutput(#[from] std::fmt::Error),

    #[error(transparent)]
    Unexpected(#[from] eyre::Report),
}
