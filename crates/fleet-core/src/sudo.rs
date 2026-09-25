//! Per-server sudo passwords (design §5.9): random, 24 characters,
//! different on every server, kept in the Keychain and synced end-to-end
//! encrypted (`sync::Collection::SudoPasswords`). Revealed only on request
//! behind Touch ID and never typed automatically.

use fleet_crypto::Zeroizing;

pub const LENGTH: usize = 24;
/// Unambiguous letters and digits plus a few symbols that need no quoting
/// in `chpasswd` input or a terminal paste (no `:`, quotes, `\`, space).
const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_.+=@%";

/// A fresh password (~143 bits: 24 characters from 64 symbols).
pub fn generate() -> Result<Zeroizing<String>, fleet_crypto::Error> {
    let mut out = Zeroizing::new(String::with_capacity(LENGTH));
    let mut buf = Zeroizing::new([0u8; 64]);
    while out.len() < LENGTH {
        fleet_crypto::random_bytes(buf.as_mut())?;
        for b in buf.iter() {
            // 64 symbols: every byte maps without bias.
            out.push(char::from(ALPHABET[usize::from(*b) % ALPHABET.len()]));
            if out.len() == LENGTH {
                break;
            }
        }
    }
    Ok(out)
}

/// A synced password must look like one of ours (it came from another Mac,
/// but is still checked before it is stored or shown).
pub fn is_valid(p: &str) -> bool {
    p.len() == LENGTH && p.bytes().all(|b| ALPHABET.contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_passwords_are_valid_and_distinct() {
        assert_eq!(ALPHABET.len(), 64);
        let a = generate().unwrap();
        let b = generate().unwrap();
        assert!(is_valid(&a) && is_valid(&b));
        assert_ne!(*a, *b);
        assert!(!is_valid("short"));
        assert!(!is_valid(&"a:".repeat(12)));
    }
}
