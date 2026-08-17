//! Captured-request (POST replay) tests. Own test crate; public API only.

use pow_gate_core::replay::{inject, method_replayable, Captured, SCRIPT_ID};

fn payload_of(method: &str, url: &str, ct: &str, body: &[u8]) -> String {
    Captured::new(method, url, ct, body)
        .unwrap_or_else(|| panic!("{method} {url} should be capturable"))
        .payload()
}

#[test]
fn payload_carries_method_url_type_and_body() {
    let p = payload_of(
        "POST",
        "/order?ref=mail",
        "application/x-www-form-urlencoded",
        b"qty=2&note=hi",
    );
    let v: serde_json::Value = serde_json::from_str(&p).expect("valid json");
    assert_eq!(v["method"], "POST");
    assert_eq!(v["url"], "/order?ref=mail");
    assert_eq!(v["type"], "application/x-www-form-urlencoded");
    // base64url of the body, no padding
    assert_eq!(v["body"], "cXR5PTImbm90ZT1oaQ");
    let decoded = pow_gate_core::codec::unb64url(v["body"].as_str().unwrap()).unwrap();
    assert_eq!(decoded, b"qty=2&note=hi");
}

#[test]
fn every_method_that_can_carry_data_is_replayed() {
    // Deny-list, not allow-list: the declared body decides, not a verb table.
    for m in ["POST", "post", "PUT", "PATCH", "DELETE", "OPTIONS", "REPORT",
              "SEARCH", "PROPFIND", "PROPPATCH", "LOCK", "MKCOL", "WHATEVER"] {
        assert!(method_replayable(m), "{m} should be replayable");
        assert!(Captured::new(m, "/x", "", b"a").is_some());
    }
    // …except the ones with nothing to keep, plus junk tokens.
    for m in ["GET", "get", "HEAD", "TRACE", "CONNECT", "", "PO ST", "P\rST", "PUT2"] {
        assert!(!method_replayable(m), "{m:?} must not be replayed");
        assert!(Captured::new(m, "/x", "", b"a").is_none());
    }
}

#[test]
fn the_method_is_echoed_verbatim() {
    // HTTP methods are case-sensitive — a replay must not "normalize" one.
    let p = payload_of("PropFind", "/x", "", b"a");
    let v: serde_json::Value = serde_json::from_str(&p).unwrap();
    assert_eq!(v["method"], "PropFind");
}

#[test]
fn only_same_site_paths_are_replayed() {
    // A cross-origin or otherwise unsafe target degrades to no replay at all —
    // the client just gets the plain challenge page.
    for bad in [
        "//evil.example/x",
        "http://evil.example/x",
        "relative",
        "/a b",
        "/a\"b",
        "/<script>",
        "/a\\b",
        "/a\r\nX: 1",
    ] {
        assert!(Captured::new("POST", bad, "", b"a").is_none(), "{bad:?}");
    }
}

#[test]
fn payload_can_never_close_its_script_block() {
    // Everything hostile arrives through the Content-Type here (the URL is held
    // to same_site_path, the body is base64) — it must come out escaped.
    let p = payload_of("POST", "/x", "text/plain</script><script>alert(1)", b"");
    assert!(!p.contains('<'), "payload must not contain a raw '<': {p}");
    assert!(!p.contains('>'));
    assert!(!p.contains('&'));
    // …and still be the value it was, once parsed as JSON
    let v: serde_json::Value = serde_json::from_str(&p).unwrap();
    assert_eq!(v["type"], "text/plain</script><script>alert(1)");
}

#[test]
fn control_bytes_are_stripped_from_the_content_type() {
    let p = payload_of("POST", "/x", "text/plain\r\nX-Injected: 1", b"");
    let v: serde_json::Value = serde_json::from_str(&p).unwrap();
    assert_eq!(v["type"], "text/plainX-Injected: 1");
}

#[test]
fn injected_before_the_closing_body_tag() {
    let page = b"<html><body><p>hi</p></BODY></html>\n";
    let tag = Captured::new("POST", "/x", "", b"a").unwrap().script_tag();
    let out = String::from_utf8(inject(page, &tag)).unwrap();
    assert!(out.contains(&format!("id=\"{SCRIPT_ID}\"")));
    let script_at = out.find("<script").unwrap();
    let body_at = out.to_lowercase().rfind("</body>").unwrap();
    assert!(script_at < body_at, "script must precede </body>: {out}");
    assert!(out.ends_with("</BODY></html>\n"));
}

#[test]
fn page_without_a_body_tag_still_gets_the_payload() {
    let tag = Captured::new("POST", "/x", "", b"a").unwrap().script_tag();
    let out = String::from_utf8(inject(b"just text", &tag)).unwrap();
    assert!(out.starts_with("just text"));
    assert!(out.contains(&format!("id=\"{SCRIPT_ID}\"")));
}
