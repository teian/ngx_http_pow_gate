//! Parsing of `pow_gate_decision` values — the per-request verdict string the
//! operator produces with a native `map`.
//!
//! Grammar (first form that matches wins; anything unparsable falls back to the
//! default JS challenge, so a typo in a `map` can never open the gate):
//!
//! ```text
//!   allow                    pass to upstream
//!   deny                     403
//!   verify:<name>            good-bot verifier (IP ranges / FCrDNS)
//!   challenge                JS proof-of-work, configured difficulty
//!   challenge:<N>            JS proof-of-work, difficulty N for this client
//!   challenge:js             JS execution proof only (difficulty 1 — the
//!                            keypair + verify roundtrip is the whole test)
//!   challenge:nojs           no-JS meta-refresh challenge, default delay
//!   challenge:nojs:<secs>    no-JS meta-refresh challenge, explicit delay
//! ```

/// Default wait (seconds) for the no-JS meta-refresh challenge.
pub const NOJS_DEFAULT_DELAY: i64 = 2;
/// Clamp bounds for the operator-chosen no-JS delay.
pub const NOJS_MIN_DELAY: i64 = 1;
pub const NOJS_MAX_DELAY: i64 = 30;

/// A parsed `pow_gate_decision` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision<'a> {
    /// JS proof-of-work challenge. `difficulty` overrides the configured value
    /// for this client when set (`challenge:<N>` / `challenge:js`).
    Challenge { difficulty: Option<u64> },
    /// No-JS meta-refresh challenge with a `delay`-second minimum wait.
    ChallengeNoJs { delay: i64 },
    Allow,
    Deny,
    /// Good-bot verifier by name.
    Verify(&'a str),
}

impl<'a> Decision<'a> {
    /// Parse a decision string. Unknown or malformed values become the default
    /// challenge — fail safe, never fail open.
    pub fn parse(s: &'a str) -> Decision<'a> {
        match s {
            "allow" => return Decision::Allow,
            "deny" => return Decision::Deny,
            "" | "challenge" => return Decision::Challenge { difficulty: None },
            _ => {}
        }
        match s.split_once(':') {
            Some(("verify", name)) if !name.is_empty() => Decision::Verify(name),
            Some(("challenge", arg)) => match arg {
                "js" => Decision::Challenge { difficulty: Some(1) },
                "nojs" => Decision::ChallengeNoJs { delay: NOJS_DEFAULT_DELAY },
                _ => {
                    if let Some(secs) = arg.strip_prefix("nojs:") {
                        let delay = secs
                            .parse::<i64>()
                            .unwrap_or(NOJS_DEFAULT_DELAY)
                            .clamp(NOJS_MIN_DELAY, NOJS_MAX_DELAY);
                        Decision::ChallengeNoJs { delay }
                    } else if let Ok(n) = arg.parse::<u64>() {
                        Decision::Challenge { difficulty: Some(n.max(1)) }
                    } else {
                        Decision::Challenge { difficulty: None }
                    }
                }
            },
            _ => Decision::Challenge { difficulty: None },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_values() {
        assert_eq!(Decision::parse("allow"), Decision::Allow);
        assert_eq!(Decision::parse("deny"), Decision::Deny);
        assert_eq!(Decision::parse(""), Decision::Challenge { difficulty: None });
        assert_eq!(Decision::parse("challenge"), Decision::Challenge { difficulty: None });
        assert_eq!(Decision::parse("verify:search"), Decision::Verify("search"));
    }

    #[test]
    fn challenge_variants() {
        assert_eq!(
            Decision::parse("challenge:200000"),
            Decision::Challenge { difficulty: Some(200000) }
        );
        assert_eq!(Decision::parse("challenge:js"), Decision::Challenge { difficulty: Some(1) });
        assert_eq!(
            Decision::parse("challenge:nojs"),
            Decision::ChallengeNoJs { delay: NOJS_DEFAULT_DELAY }
        );
        assert_eq!(Decision::parse("challenge:nojs:5"), Decision::ChallengeNoJs { delay: 5 });
    }

    #[test]
    fn clamps_and_fail_safe() {
        // zero difficulty is meaningless -> floor of 1
        assert_eq!(Decision::parse("challenge:0"), Decision::Challenge { difficulty: Some(1) });
        // delay clamped to sane bounds
        assert_eq!(
            Decision::parse("challenge:nojs:0"),
            Decision::ChallengeNoJs { delay: NOJS_MIN_DELAY }
        );
        assert_eq!(
            Decision::parse("challenge:nojs:999"),
            Decision::ChallengeNoJs { delay: NOJS_MAX_DELAY }
        );
        assert_eq!(
            Decision::parse("challenge:nojs:xyz"),
            Decision::ChallengeNoJs { delay: NOJS_DEFAULT_DELAY }
        );
        // junk never opens the gate
        assert_eq!(Decision::parse("challenge:huh"), Decision::Challenge { difficulty: None });
        assert_eq!(Decision::parse("banana"), Decision::Challenge { difficulty: None });
        assert_eq!(Decision::parse("verify:"), Decision::Challenge { difficulty: None });
    }
}
