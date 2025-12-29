use core::fmt::Write;
use eyre::eyre;

pub(super) fn encode(bytes: &[u8], need_prefix: bool) -> Result<String, eyre::Error> {
    let len = (bytes.len() + usize::from(need_prefix)) * 2;

    let mut s = String::with_capacity(len);

    if need_prefix {
        write!(s, "0x")?;
    }

    for b in bytes {
        write!(&mut s, "{b:02x}")?;
    }

    Ok(s)
}

pub(super) fn decode(s: &str) -> Result<Vec<u8>, eyre::Error> {
    let s = s.strip_prefix("0x").unwrap_or(s);

    if !s.len().is_multiple_of(2) {
        return Err(eyre!("hex string has odd length"));
    }

    let mut out = Vec::with_capacity(s.len() / 2);

    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = from_hex_char(bytes[i])?;
        let lo = from_hex_char(bytes[i + 1])?;
        out.push((hi << 4) | lo);
    }

    Ok(out)
}

fn from_hex_char(c: u8) -> Result<u8, eyre::Error> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(eyre!("invalid hex character")),
    }
}
