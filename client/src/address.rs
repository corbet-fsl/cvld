//! Community addresses: one shared validator and suggester for server and browser.
//!
//! An address is the permanent subdomain label `<address>.<base>` of a community.
//! Rule: `^[a-z0-9]{8,30}$`, not reserved, not offensive. Every name shorter than
//! eight characters is reserved by length alone (which covers every platform host label,
//! see `hub::PLATFORM_HOST_LABELS`, that the hub also refuses by name); the Root-maintained
//! list is a setting handed in by the caller. Uniqueness among live communities is a
//! registry matter and is checked by the server, not here.
use rustrict::CensorStr;

pub const MIN_LEN: usize = 8;
pub const MAX_LEN: usize = 30;

/// Why an address is not acceptable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    TooShort,
    TooLong,
    /// Anything outside lowercase a-z and 0-9.
    Charset,
    Reserved,
    Offensive,
}

/// Length hint for the creation form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Light {
    Red,
    Amber,
    Green,
}

/// Normalised Root-maintained reserved list (lowercase a-z0-9 entries).
#[derive(Debug, Clone, Default)]
pub struct Reserved(std::collections::BTreeSet<String>);

impl Reserved {
    pub fn new<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self(
            names
                .into_iter()
                .map(|n| n.as_ref().trim().to_ascii_lowercase())
                .filter(|n| !n.is_empty())
                .collect(),
        )
    }
    pub fn contains(&self, address: &str) -> bool {
        self.0.contains(address)
    }
}

/// Check the syntax only (length and charset).
pub fn check_syntax(address: &str) -> Result<(), Refusal> {
    if !address
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return Err(Refusal::Charset);
    }
    match address.len() {
        n if n < MIN_LEN => Err(Refusal::TooShort),
        n if n > MAX_LEN => Err(Refusal::TooLong),
        _ => Ok(()),
    }
}

/// Full validation: syntax, reserved list, offensive-name filter.
pub fn validate(address: &str, reserved: &Reserved) -> Result<(), Refusal> {
    check_syntax(address)?;
    if reserved.contains(address) {
        return Err(Refusal::Reserved);
    }
    if address.is_inappropriate() {
        return Err(Refusal::Offensive);
    }
    Ok(())
}

/// Traffic light for the length: red is unusable, green is comfortable to type,
/// amber is valid but long.
pub fn light(address: &str) -> Light {
    match address.len() {
        n if !(MIN_LEN..=MAX_LEN).contains(&n) => Light::Red,
        n if n <= 20 => Light::Green,
        _ => Light::Amber,
    }
}

/// Transliterate free text to ascii and keep lowercase words of a-z0-9.
fn words(display_name: &str) -> Vec<String> {
    let ascii = any_ascii::any_ascii(display_name).to_ascii_lowercase();
    ascii
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_owned)
        .collect()
}

const FILLERS: [&str; 4] = ["club", "team", "hub", "circle"];

/// Short, deterministic candidates derived from a display name. Every returned
/// address passes [`validate`]; the server still checks availability.
pub fn suggest(display_name: &str, reserved: &Reserved, limit: usize) -> Vec<String> {
    let words = words(display_name);
    if words.is_empty() || limit == 0 {
        return Vec::new();
    }
    let joined: String = words.concat();
    let initials: String = words.iter().filter_map(|w| w.chars().next()).collect();
    let mut bases = vec![joined.clone()];
    if words.len() > 1 {
        // First word with the initials of the rest, then the first two words.
        let rest: String = words[1..].iter().filter_map(|w| w.chars().next()).collect();
        bases.push(format!("{}{}", words[0], rest));
        bases.push(words[..2].concat());
    }
    bases.push(initials);
    let mut out: Vec<String> = Vec::new();
    let mut push = |candidate: String| {
        let candidate: String = candidate.chars().take(MAX_LEN).collect();
        if validate(&candidate, reserved).is_ok() && !out.contains(&candidate) {
            out.push(candidate);
        }
    };
    for base in &bases {
        push(base.clone());
    }
    for base in &bases {
        for filler in FILLERS {
            let room = MAX_LEN - filler.len();
            let head: String = base.chars().take(room).collect();
            push(format!("{head}{filler}"));
        }
    }
    for base in &bases {
        for n in 2..10u8 {
            let head: String = base.chars().take(MAX_LEN - 1).collect();
            push(format!("{head}{n}"));
        }
    }
    for base in &bases {
        for filler in FILLERS {
            for n in 10..100u8 {
                let head: String = base.chars().take(MAX_LEN - filler.len() - 2).collect();
                push(format!("{head}{filler}{n}"));
            }
        }
    }
    out.truncate(limit);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn none() -> Reserved {
        Reserved::default()
    }

    #[test]
    fn syntax_bounds() {
        assert_eq!(check_syntax("abcdefg"), Err(Refusal::TooShort));
        assert_eq!(check_syntax("abcdefgh"), Ok(()));
        assert_eq!(check_syntax(&"a".repeat(30)), Ok(()));
        assert_eq!(check_syntax(&"a".repeat(31)), Err(Refusal::TooLong));
        for bad in [
            "abcd-efgh",
            "ABCDEFGH",
            "abcdefgh!",
            "abcdefgé",
            "abcd efgh",
        ] {
            assert_eq!(check_syntax(bad), Err(Refusal::Charset), "{bad}");
        }
    }

    #[test]
    fn reserved_names_are_refused() {
        let reserved = Reserved::new(["Wallet1234", " vaultvault "]);
        assert_eq!(validate("wallet1234", &reserved), Err(Refusal::Reserved));
        assert_eq!(validate("vaultvault", &reserved), Err(Refusal::Reserved));
        assert_eq!(validate("walletabcd", &reserved), Ok(()));
        // Names under eight characters are reserved by length with an empty list.
        assert_eq!(validate("vault", &none()), Err(Refusal::TooShort));
    }

    #[test]
    fn offensive_names_are_refused() {
        assert_eq!(validate("fuckyou12", &none()), Err(Refusal::Offensive));
        assert_eq!(validate("gardenclub", &none()), Ok(()));
    }

    #[test]
    fn light_follows_length() {
        assert_eq!(light("short"), Light::Red);
        assert_eq!(light("eightchr"), Light::Green);
        assert_eq!(light(&"a".repeat(21)), Light::Amber);
        assert_eq!(light(&"a".repeat(31)), Light::Red);
    }

    #[test]
    fn suggestions_are_valid_and_transliterated() {
        let reserved = Reserved::new(["zuerichfans"]);
        let got = suggest("Zürich Fans!", &reserved, 6);
        assert!(!got.is_empty() && got.len() <= 6);
        for s in &got {
            assert_eq!(validate(s, &reserved), Ok(()), "{s}");
        }
        assert!(!got.contains(&"zuerichfans".to_owned()));
        assert!(got.iter().any(|s| s.starts_with("zurich")));
        let again = suggest("Zürich Fans!", &reserved, 6);
        assert_eq!(got, again);
    }

    #[test]
    fn short_names_get_padded_and_empty_names_get_nothing() {
        let got = suggest("Ab", &none(), 3);
        assert_eq!(got.len(), 3);
        assert!(got.iter().all(|s| s.starts_with("ab")));
        assert!(suggest("!!!", &none(), 3).is_empty());
        assert!(suggest("Ab", &none(), 0).is_empty());
    }

    #[test]
    fn long_names_are_truncated() {
        let got = suggest(&"x".repeat(80), &none(), 2);
        assert!(got.iter().all(|s| s.len() <= MAX_LEN));
    }
}
