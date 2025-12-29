use crate::errors::WalletBipError;
use bip39::{Language, Mnemonic, rand};
use rand::seq::SliceRandom;
use std::collections::HashSet;

/// The minimum number of words in a mnemonic.
const MIN_NB_WORDS: usize = 12;

/// The maximum number of words in a mnemonic.
const MAX_NB_WORDS: usize = 24;

pub fn generate(word_count: usize, lang: Language) -> crate::Result<Vec<&'static str>> {
    Ok(Mnemonic::generate_in(lang, word_count)?.words().collect())
}

pub fn is_mnemonic(word: &str, lang: Language) -> bool {
    lang.word_list().contains(&word)
}

fn is_invalid_word_count(word_count: usize) -> bool {
    word_count < MIN_NB_WORDS || !word_count.is_multiple_of(3) || word_count > MAX_NB_WORDS
}

pub fn split<'a>(mnemonic: &[&'a str]) -> crate::Result<Vec<&'a str>> {
    static HIDED: &str = "XXXX";

    if is_invalid_word_count(mnemonic.len()) {
        return Err(WalletBipError::SplitMnemonic(
            "invalid word count".to_string(),
        ));
    }

    let mut values = (0..mnemonic.len()).collect::<Vec<_>>();
    values.shuffle(&mut rand::thread_rng());

    values.truncate(mnemonic.len() / 3);
    let values = values.into_iter().collect::<HashSet<_>>();

    Ok(mnemonic
        .iter()
        .enumerate()
        .map(|(idx, &word)| if values.contains(&idx) { HIDED } else { word })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_mnemonic() {
        let result = generate(12, Language::English).unwrap();

        assert_eq!(result.len(), 12);
    }

    #[test]
    fn test_generate_mnemonic_invalid_word_count() {
        assert!(generate(10, Language::English).is_err());
    }

    #[test]
    fn test_check_word_for_mnemonic() {
        assert!(is_mnemonic("jar", Language::English));
    }

    #[test]
    fn test_check_word_for_mnemonic_invalid() {
        assert!(!is_mnemonic("jak", Language::English));
    }

    #[test]
    fn test_split_mnemonic() {
        let mnemonic = generate(12, Language::English).unwrap();

        let result1 = split(&mnemonic).unwrap();
        let result2 = split(&mnemonic).unwrap();

        assert_eq!(result1.len(), 12);
        assert_eq!(result2.len(), 12);
        assert_ne!(result1, result2);
    }
}
