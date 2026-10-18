use pow_gate_core::redis::{self, Reply};
#[test]
fn resp_frames_handle_fragmentation_without_trusting_server_lengths() {
    for partial in [b"".as_slice(), b":", b":1\r", b"-ERR wrong"] {
        assert_eq!(redis::reply(partial), Ok(None));
    }
    assert_eq!(
        redis::reply(b":1\r\n:0\r\n"),
        Ok(Some((Reply::Integer(1), 4)))
    );
    assert_eq!(redis::reply(b":-2\r\n"), Ok(Some((Reply::Integer(-2), 5))));
    assert_eq!(redis::reply(b"+OK\r\n"), Ok(Some((Reply::Ok, 5))));
    assert_eq!(
        redis::reply(b"-OOM details\r\n"),
        Ok(Some((Reply::Error, 14)))
    );
    assert!(redis::reply(b"$99999999999999\r\n").is_err());
    assert!(redis::reply(&vec![b'x'; 1025]).is_err());
    assert!(redis::reply(b":99999999999999999999999999\r\n").is_err());
}
#[test]
fn resp_encoding_cannot_inject_commands() {
    assert_eq!(
        redis::command(&[b"AUTH", b"a\r\nPING"]),
        b"*2\r\n$4\r\nAUTH\r\n$7\r\na\r\nPING\r\n"
    );
    let a = redis::keys("site", "epoch", "challenge");
    assert_eq!(a[0], "powgate:{site}:epoch");
    assert_ne!(a[1], redis::keys("other", "epoch", "challenge")[1]);
    assert_ne!(a[1], redis::keys("site", "new-epoch", "challenge")[1]);
    assert_eq!(a[1], redis::keys("site", "epoch", "challenge")[1]);
}
