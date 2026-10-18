//! Compare the bounded decoder with the pre-optimization wire checks, including
//! authenticated malformed/escaped JSON and the allocation cost of valid tokens.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use hmac::{Hmac, Mac};
use pow_gate_core::{
    clearance::{self, Clearance},
    codec,
    context::Assurance,
    HmacKey,
};
use sha2::Sha256;

struct CountingAllocator;
thread_local! {
    static ALLOCATIONS: Cell<Option<usize>> = const { Cell::new(None) };
}
fn allocated() {
    let _ = ALLOCATIONS.try_with(|count| {
        if let Some(value) = count.get() {
            count.set(Some(value + 1));
        }
    });
}
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        allocated();
        System.alloc(layout)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        allocated();
        System.alloc_zeroed(layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        allocated();
        System.realloc(ptr, layout, size)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
}
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

const KEY: &[u8] = b"bounded-clearance-test-secret-32-bytes";
const REQUIRED: Assurance = Assurance::Pow { difficulty: 2000 };

fn signed(payload: &[u8]) -> String {
    let payload = codec::b64url(payload);
    let mut mac = Hmac::<Sha256>::new_from_slice(KEY).unwrap();
    mac.update(b"pow-gate-clearance-v2|");
    mac.update(payload.as_bytes());
    format!("{payload}.{}", codec::b64url(&mac.finalize().into_bytes()))
}

// Kept independent of the optimized verifier: the original owned JSON decoder
// and every original acceptance check, using RustCrypto to authenticate bytes.
fn reference(
    token: &str,
    context: &str,
    required: Assurance,
    now: i64,
    age: i64,
) -> Option<Clearance> {
    if token.len() > 4096 {
        return None;
    }
    let (payload, tag) = token.split_once('.')?;
    let mut mac = Hmac::<Sha256>::new_from_slice(KEY).unwrap();
    mac.update(b"pow-gate-clearance-v2|");
    mac.update(payload.as_bytes());
    mac.verify_slice(&codec::unb64url(tag)?).ok()?;
    let value: Clearance = serde_json::from_slice(&codec::unb64url(payload)?).ok()?;
    if value.version != 2
        || value.context != context
        || !value.assurance.satisfies(required)
        || value.exp <= now
        || value.iat > now
        || age <= 0
        || now.checked_sub(value.iat)? >= age
    {
        return None;
    }
    let pk = value.pk_bytes()?;
    match value.assurance {
        Assurance::Pow { .. } if pk.len() != 65 || pk[0] != 4 => return None,
        Assurance::NoJs { .. } if !pk.is_empty() => return None,
        _ => {}
    }
    Some(value)
}

fn compare(token: &str, context: &str, required: Assurance, now: i64, age: i64) {
    let expected = reference(token, context, required, now, age);
    let key = HmacKey::new(KEY);
    let mut calls = 0;
    let got =
        clearance::with_verified_prepared(&key, token, context, required, now, age, |value| {
            calls += 1;
            assert_eq!(
                value.public_key(),
                expected.as_ref().unwrap().pk_bytes().unwrap()
            );
            value.into_owned()
        });
    assert_eq!(got, expected, "token {token:?}, now {now}, age {age}");
    assert_eq!(calls, usize::from(expected.is_some()));
    assert_eq!(
        clearance::verify_prepared(&key, token, context, required, now, age),
        expected
    );
}

fn payload() -> serde_json::Value {
    // Cookie-only validation checks canonical shape, as before. Actual curve
    // validity is checked at issuance and during request-proof verification.
    let mut pk = [42; 65];
    pk[0] = 4;
    serde_json::json!({"version":2,"pk":codec::b64url(&pk),"context":"context","assurance":{"kind":"pow","difficulty":2000},"iat":1000,"exp":2000})
}

#[test]
fn matches_original_for_lifetime_context_assurance_and_key_boundaries() {
    let good = payload();
    let mut cases = vec![good.clone()];
    for field in ["version", "pk", "context", "assurance", "iat", "exp"] {
        let mut value = good.clone();
        value.as_object_mut().unwrap().remove(field);
        cases.push(value);
    }
    for (field, values) in [
        (
            "version",
            vec![serde_json::json!(1), serde_json::json!(256)],
        ),
        (
            "iat",
            vec![
                serde_json::json!(i64::MIN),
                serde_json::json!(1501),
                serde_json::json!(i64::MAX),
            ],
        ),
        (
            "exp",
            vec![
                serde_json::json!(i64::MIN),
                serde_json::json!(1500),
                serde_json::json!(i64::MAX),
            ],
        ),
        (
            "context",
            vec![serde_json::json!("other"), serde_json::json!(null)],
        ),
    ] {
        for item in values {
            let mut value = good.clone();
            value[field] = item;
            cases.push(value);
        }
    }
    for size in [0, 1, 33, 64, 65, 66, 128] {
        for first in [0, 2, 3, 4, 255] {
            let mut pk = vec![42; size];
            if !pk.is_empty() {
                pk[0] = first;
            }
            let mut value = good.clone();
            value["pk"] = serde_json::json!(codec::b64url(&pk));
            cases.push(value);
        }
    }
    for assurance in [
        serde_json::json!({"kind":"pow","difficulty":0}),
        serde_json::json!({"kind":"pow","difficulty":1999}),
        serde_json::json!({"kind":"no_js","delay":2}),
        serde_json::json!({"kind":"unknown"}),
    ] {
        let mut value = good.clone();
        value["assurance"] = assurance;
        cases.push(value);
    }
    for value in cases {
        let token = signed(&serde_json::to_vec(&value).unwrap());
        for (now, age) in [
            (999, 1000),
            (1000, 1000),
            (1500, 500),
            (1500, 501),
            (1999, 2000),
            (2000, 2000),
            (i64::MAX, i64::MAX),
        ] {
            compare(&token, "context", REQUIRED, now, age);
        }
    }
    for delay in [0, 1, 2, 3, 30] {
        let token = clearance::issue(KEY, &[], "context", Assurance::NoJs { delay }, 1000, 1000);
        compare(&token, "context", Assurance::NoJs { delay: 2 }, 1500, 1000);
        compare(&token, "context", REQUIRED, 1500, 1000);
    }
}

#[test]
fn preserves_escaped_json_unknown_fields_duplicate_rejection_and_size_limits() {
    let mut value = payload();
    let context = "escaped\"\\\n雪";
    value["context"] = serde_json::json!(context);
    let raw = serde_json::to_string(&value)
        .unwrap()
        .replace("context\"", "\\u0063ontext\"");
    compare(&signed(raw.as_bytes()), context, REQUIRED, 1500, 1000);
    // Escape a character in the base64 key as well as its JSON field name.
    let raw = serde_json::to_string(&payload())
        .unwrap()
        .replace("BCoq", "\\u0042Coq");
    assert!(raw.contains("\\u0042"));
    compare(&signed(raw.as_bytes()), "context", REQUIRED, 1500, 1000);
    let raw = serde_json::to_string(&payload()).unwrap();
    for extra in [
        r#", "version":2"#.to_owned(),
        r#", "pk":"""#.to_owned(),
        r#", "context":"context""#.to_owned(),
        r#", "extra":null"#.to_owned(),
    ] {
        compare(
            &signed(format!("{}{extra}}}", &raw[..raw.len() - 1]).as_bytes()),
            "context",
            REQUIRED,
            1500,
            1000,
        );
    }
    for size in [0, 2000, 2800, 3000, 3100, 4096] {
        let mut value = payload();
        value["extra"] = serde_json::json!("a".repeat(size));
        compare(
            &signed(&serde_json::to_vec(&value).unwrap()),
            "context",
            REQUIRED,
            1500,
            1000,
        );
    }
    let mut exact_limit = false;
    for size in 2700..3100 {
        let mut value = payload();
        value["extra"] = serde_json::json!("a".repeat(size));
        let token = signed(&serde_json::to_vec(&value).unwrap());
        if (4095..=4100).contains(&token.len()) {
            compare(&token, "context", REQUIRED, 1500, 1000);
            exact_limit |=
                token.len() == 4096 && reference(&token, "context", REQUIRED, 1500, 1000).is_some();
        }
    }
    assert!(exact_limit);
    for raw in [b"not json".as_slice(), b"{\"pk\":\"\xff\"}", b"[]", b"null"] {
        compare(&signed(raw), "context", REQUIRED, 1500, 1000);
    }
}

#[test]
fn rejects_tampering_before_invoking_the_callback() {
    let token = signed(&serde_json::to_vec(&payload()).unwrap());
    for i in 0..token.len() {
        let mut changed = token.as_bytes().to_vec();
        changed[i] = if changed[i] == b'A' { b'B' } else { b'A' };
        compare(
            std::str::from_utf8(&changed).unwrap(),
            "context",
            REQUIRED,
            1500,
            1000,
        );
    }
    for token in ["", "a.b.c", "no-dot", "e30."] {
        compare(token, "context", REQUIRED, 1500, 1000);
    }
}

#[test]
fn fixed_width_decoders_match_strict_vector_decoding() {
    fn width<const N: usize>() {
        for size in [N.saturating_sub(1), N, N + 1] {
            for byte in [0, 1, 42, 255] {
                let encoded = codec::b64url(&vec![byte; size]);
                let expected = codec::unb64url(&encoded).and_then(|v| v.try_into().ok());
                assert_eq!(codec::unb64url_fixed::<N>(&encoded), expected);
            }
        }
        for encoded in ["!", "A", "AA=", "AB", "__", "AA.A", "\nAA"] {
            let expected = codec::unb64url(encoded).and_then(|v| v.try_into().ok());
            assert_eq!(codec::unb64url_fixed::<N>(encoded), expected);
        }
    }
    width::<0>();
    width::<1>();
    width::<2>();
    width::<3>();
    width::<32>();
    width::<64>();
    width::<65>();
}

#[test]
fn borrowed_verification_reduces_allocations_for_normal_wire_tokens() {
    let token = signed(&serde_json::to_vec(&payload()).unwrap());
    let key = HmacKey::new(KEY);
    assert!(clearance::verify_prepared(&key, &token, "context", REQUIRED, 1500, 1000).is_some());
    ALLOCATIONS.with(|count| count.set(Some(0)));
    let old = reference(&token, "context", REQUIRED, 1500, 1000);
    let owned = ALLOCATIONS.with(|count| count.replace(None).unwrap());
    assert!(old.is_some());
    ALLOCATIONS.with(|count| count.set(Some(0)));
    let new =
        clearance::with_verified_prepared(&key, &token, "context", REQUIRED, 1500, 1000, |value| {
            value.public_key().len()
        });
    let borrowed = ALLOCATIONS.with(|count| count.replace(None).unwrap());
    assert_eq!(new, Some(65));
    assert!(borrowed + 3 <= owned, "old={owned}, borrowed={borrowed}");
    println!("Clearance validation allocations: original={owned}, borrowed={borrowed}");
}
