//! No-JS grant tests. Own test crate; public API only.

use pow_gate_core::nojs::{issue, verify, Verdict, NOJS_GRACE};

const KEY: &[u8] = b"server-secret-key";

#[test]
fn honours_the_wait_then_redeems() {
    let t = issue(KEY, "/wiki/Seite?x=1", 2, 1000);
    // immediately: too early, path preserved for the re-challenge
    match verify(KEY, &t, 1000) {
        Verdict::TooEarly(g) => assert_eq!(g.path, "/wiki/Seite?x=1"),
        v => panic!("expected TooEarly, got {v:?}"),
    }
    match verify(KEY, &t, 1001) {
        Verdict::TooEarly(_) => {}
        v => panic!("expected TooEarly, got {v:?}"),
    }
    // after the delay: ok
    match verify(KEY, &t, 1002) {
        Verdict::Ok(g) => {
            assert_eq!(g.path, "/wiki/Seite?x=1");
            assert_eq!(g.delay, 2);
        }
        v => panic!("expected Ok, got {v:?}"),
    }
}

#[test]
fn expires_after_grace() {
    let t = issue(KEY, "/", 2, 1000);
    assert_eq!(verify(KEY, &t, 1000 + NOJS_GRACE), Verdict::Bad);
}

#[test]
fn rejects_forgery_and_wrong_key() {
    let t = issue(KEY, "/", 2, 1000);
    assert_eq!(verify(b"other-key-entirely", &t, 1005), Verdict::Bad);
    assert_eq!(verify(KEY, "garbage", 1005), Verdict::Bad);
    assert_eq!(verify(KEY, "", 1005), Verdict::Bad);
    // tamper with the payload half
    let (_, tag) = t.split_once('.').unwrap();
    let forged = format!("eyJmb28iOjF9.{tag}");
    assert_eq!(verify(KEY, &forged, 1005), Verdict::Bad);
}

#[test]
fn grant_is_not_a_clearance_and_vice_versa() {
    // Domain separation: a nojs grant must not verify as a clearance cookie,
    // and a clearance must not redeem as a grant.
    let grant = issue(KEY, "/", 2, 1000);
    assert!(pow_gate_core::clearance::verify(KEY, &grant, 1005).is_none());

    let clearance = pow_gate_core::clearance::issue(KEY, b"", 1000, 3600);
    assert_eq!(verify(KEY, &clearance, 1005), Verdict::Bad);
}

#[test]
fn unsafe_paths_never_come_back() {
    // issue() degrades unsafe paths to "/"
    let t = issue(KEY, "//evil.example/", 2, 1000);
    match verify(KEY, &t, 1003) {
        Verdict::Ok(g) => assert_eq!(g.path, "/"),
        v => panic!("expected Ok, got {v:?}"),
    }
    let t = issue(KEY, "no-leading-slash", 2, 1000);
    match verify(KEY, &t, 1003) {
        Verdict::Ok(g) => assert_eq!(g.path, "/"),
        v => panic!("expected Ok, got {v:?}"),
    }
    // header-injection and markup bytes degrade to "/" as well
    for bad in ["/a\r\nSet-Cookie: x=1", "/a b", "/a\"b", "/<script>", "/a\\b"] {
        let t = issue(KEY, bad, 2, 1000);
        match verify(KEY, &t, 1003) {
            Verdict::Ok(g) => assert_eq!(g.path, "/", "path {bad:?} must degrade"),
            v => panic!("expected Ok, got {v:?}"),
        }
    }
}
