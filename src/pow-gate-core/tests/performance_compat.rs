//! Optimizations must preserve v2 authentication and the verifier's decisions.
use hmac::{Hmac, Mac};
use p256::ecdsa::SigningKey;
#[cfg(feature = "native-crypto")]
use p256::ecdsa::{signature::Signer, Signature};
use pow_gate_core::{
    clearance, codec,
    context::{self, AddressPolicy, Assurance, Scope},
    HmacKey,
};
use rand_core::OsRng;
use sha2::Sha256;

const KEY: &[u8] = b"performance-compatibility-key-32-bytes";

#[test]
fn prepared_scope_preserves_json_and_host_isolation() {
    for domain in [None, Some(".ExAmPlE.Org"), Some("..example.org")] {
        let fields = ["pow_\"cookie", "/a\\b", "/.pow/", "policy\n雪"];
        let scope = Scope::new(domain, fields[0], fields[1], fields[2], fields[3]);
        for host in [
            "Example.COM",
            "..other.example",
            "☃.example",
            "quote\".example",
        ] {
            let normalized = domain
                .unwrap_or(host)
                .trim_start_matches('.')
                .to_ascii_lowercase();
            let legacy =
                serde_json::to_string(&(normalized, fields[0], fields[1], fields[2], fields[3]))
                    .unwrap();
            assert_eq!(scope.for_host(host).unwrap(), legacy);
        }
    }
    assert!(Scope::new(None, "c", "/", "/p/", "p")
        .for_host("...")
        .is_none());
    assert!(Scope::new(Some("."), "c", "/", "/p/", "p")
        .for_host("valid")
        .is_none());
    let scope = Scope::new(None, "c", "/", "/p/", "p");
    assert_ne!(scope.for_host("a.example"), scope.for_host("b.example"));
}

#[test]
fn prepared_hmac_preserves_framing_and_independent_messages() {
    for key in [KEY, b"short", &[42u8; 200]] {
        let prepared = HmacKey::new(key);
        for fields in [
            &[b"a".as_slice(), b"bc".as_slice()][..],
            &[b"ab".as_slice(), b"c".as_slice()][..],
            &[b"".as_slice(), b"\0".as_slice()][..],
        ] {
            let mut reference = Hmac::<Sha256>::new_from_slice(key).unwrap();
            for field in fields {
                reference.update(&(field.len() as u64).to_be_bytes());
                reference.update(field);
            }
            assert_eq!(
                prepared.fields(fields).as_slice(),
                &reference.finalize().into_bytes()[..]
            );
            let mut reference = Hmac::<Sha256>::new_from_slice(key).unwrap();
            for part in fields {
                reference.update(part);
            }
            assert_eq!(
                prepared.parts(fields).as_slice(),
                &reference.finalize().into_bytes()[..]
            );
        }
    }
}

#[test]
fn prepared_verification_accepts_existing_wire_token_and_rejects_changes() {
    let sk = SigningKey::random(&mut OsRng);
    let payload = serde_json::json!({"version":2,"pk":codec::b64url(sk.verifying_key().to_encoded_point(false).as_bytes()),"context":"legacy-context","assurance":{"kind":"pow","difficulty":2000},"iat":1000,"exp":2000});
    let payload = codec::b64url(&serde_json::to_vec(&payload).unwrap());
    let mut mac = Hmac::<Sha256>::new_from_slice(KEY).unwrap();
    mac.update(format!("pow-gate-clearance-v2|{payload}").as_bytes());
    let token = format!("{payload}.{}", codec::b64url(&mac.finalize().into_bytes()));
    let key = HmacKey::new(KEY);
    let required = Assurance::Pow { difficulty: 2000 };
    assert!(
        clearance::verify_prepared(&key, &token, "legacy-context", required, 1500, 1000).is_some()
    );
    assert!(
        clearance::verify_prepared(&key, &token, "other-context", required, 1500, 1000).is_none()
    );
    assert!(
        clearance::verify_prepared(&key, &token, "legacy-context", required, 2000, 1000).is_none()
    );
    for i in 0..token.len() {
        let mut changed = token.as_bytes().to_vec();
        changed[i] = if changed[i] == b'A' { b'B' } else { b'A' };
        assert!(clearance::verify_prepared(
            &key,
            std::str::from_utf8(&changed).unwrap(),
            "legacy-context",
            required,
            1500,
            1000
        )
        .is_none());
    }
    for ip in ["192.0.2.42", "2001:db8::42", "::ffff:192.0.2.42"] {
        assert_eq!(
            context::binding(
                KEY,
                ip.parse().unwrap(),
                "ua",
                "scope",
                b"issuer",
                AddressPolicy::default()
            ),
            context::binding_prepared(
                &key,
                ip.parse().unwrap(),
                "ua",
                "scope",
                b"issuer",
                AddressPolicy::default()
            )
        );
    }
}

#[cfg(feature = "native-crypto")]
#[test]
fn native_ecdsa_matches_rustcrypto_for_valid_and_invalid_signatures() {
    use p256::ecdsa::{signature::Verifier, VerifyingKey};
    use pow_gate_core::proof;
    let message = proof::message("GET", "/path?x", 1000);
    for _ in 0..24 {
        let key = SigningKey::random(&mut OsRng);
        let signature: Signature = key.sign(message.as_bytes());
        let mut signatures = vec![
            signature.to_bytes().to_vec(),
            vec![0; 64],
            vec![255; 64],
            vec![1; 63],
            vec![1; 65],
            vec![],
        ];
        // Both high-S and low-S encodings must keep their previous acceptance.
        let order = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x51,
        ];
        let mut alternate = signature.to_bytes().to_vec();
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let difference = order[i] as i16 - alternate[32 + i] as i16 - borrow;
            alternate[32 + i] = difference as u8;
            borrow = i16::from(difference < 0);
        }
        signatures.push(alternate);
        for i in 0..64 {
            let mut bad = signature.to_bytes().to_vec();
            bad[i] ^= 1;
            signatures.push(bad);
        }
        let mut keys = vec![
            key.verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
            key.verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .to_vec(),
            vec![],
            vec![0; 65],
            vec![255; 65],
        ];
        let mut wrong = keys[0].clone();
        wrong[20] ^= 1;
        keys.push(wrong);
        for pk in keys {
            for sig in &signatures {
                let expected = VerifyingKey::from_sec1_bytes(&pk)
                    .ok()
                    .and_then(|vk| {
                        Signature::from_slice(sig)
                            .ok()
                            .map(|sig| vk.verify(message.as_bytes(), &sig).is_ok())
                    })
                    .unwrap_or(false);
                assert_eq!(
                    proof::verify(&pk, "GET", "/path?x", 1000, sig, 1001, 5),
                    expected
                );
                assert!(!proof::verify(&pk, "GET", "/path?x", 1000, sig, 1010, 5));
            }
        }
    }
}

#[test]
fn indexed_ranges_match_linear_cidrs_after_overlaps_and_feed_merges() {
    use pow_gate_core::ranges::IpRangeSet;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    let mut set = IpRangeSet::new();
    let mut reference = Vec::new();
    let mut random = 0x123456789abcdef0u64;
    for i in 0..400 {
        random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
        let bits = 24 + (random % 9) as u32;
        let mask = u32::MAX << (32 - bits);
        let address = 0x0a000000 | ((random >> 32) as u32 & 0xffff);
        assert!(set.add_cidr(&format!("{}/{bits}", Ipv4Addr::from(address))));
        reference.push((address & mask, mask));
        let bits6 = 120 + (random % 9) as u32;
        assert!(set.add_cidr(&format!("2001:db8::{:x}/{bits6}", i * 3)));
    }
    for low in 0..65536u32 {
        let address = 0x0a000000 | low;
        assert_eq!(
            set.contains(IpAddr::V4(Ipv4Addr::from(address))),
            reference.iter().any(|(net, mask)| address & mask == *net)
        );
    }
    let prefixes = set.len();
    assert_eq!(set.add_feed_json(br#"{"prefixes":[{"ipv4Prefix":"192.0.2.0/24"},{"ipv4Prefix":"192.0.2.128/25"},{"ipv6Prefix":"2001:db8::/32"}]}"#), 3);
    assert_eq!(set.len(), prefixes + 3);
    for address in ["192.0.2.0", "192.0.2.255", "2001:db8:ffff::ffff"] {
        assert!(set.contains(address.parse().unwrap()));
    }
    assert!(!set.contains("192.0.3.0".parse().unwrap()));
    assert!(!set.contains("2001:db9::".parse().unwrap()));
    assert_eq!(
        set.add_feed_json(br#"{"prefixes":[{"ipv4Prefix":"0.0.0.0/0"},{"ipv6Prefix":"bad"}]}"#),
        0
    );
    assert!(!set.contains("203.0.113.1".parse().unwrap()));
    assert!(set.add_cidr("0.0.0.0/0"));
    assert!(set.add_cidr("::/0"));
    assert!(set.contains(IpAddr::V4(Ipv4Addr::from(u32::MAX))));
    assert!(set.contains(IpAddr::V6(Ipv6Addr::from(u128::MAX))));
    assert!(set.contains(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
}
