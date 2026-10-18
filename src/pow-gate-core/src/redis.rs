//! Small bounded RESP2 codec and the atomic cluster redemption transaction.
//! The nginx seam owns nonblocking transport. No request/client data is Lua code.
use crate::redemption;

pub const HEALTH: &str = "if redis.call('GET',KEYS[1])~=ARGV[1] or not tonumber(redis.call('GET',KEYS[2])) then return -2 end return 1";

// Redis is the common clock. The non-expiring high-water key prevents backward
// clock adjustments from reopening a token whose spent marker already expired.
// Epoch + high-water keys are explicitly provisioned, never recreated here.
pub const CONSUME: &str = r#"
if redis.call('GET',KEYS[1])~=ARGV[1] then return -2 end
local previous=tonumber(redis.call('GET',KEYS[3]))
if not previous then return -2 end
local current=tonumber(redis.call('TIME')[1])
local skew=tonumber(ARGV[3])
if math.abs(current-tonumber(ARGV[4]))>skew then return -3 end
local now=math.max(current,previous)
local expires=tonumber(ARGV[2])
if expires<=now then return -1 end
if now>previous then redis.call('SET',KEYS[3],tostring(now)) end
if redis.call('SET',KEYS[2],'1','NX','EX',expires-now+skew+1) then return 1 end
return 0
"#;

pub fn keys(namespace: &str, epoch: &str, token: &str) -> [String; 3] {
    let base = format!("powgate:{{{namespace}}}");
    let id: String = redemption::id(token)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    [
        format!("{base}:epoch"),
        format!("{base}:{epoch}:spent:{id}"),
        format!("{base}:clock"),
    ]
}

pub fn command(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = format!("*{}\r\n", parts.len()).into_bytes();
    for part in parts {
        out.extend_from_slice(format!("${}\r\n", part.len()).as_bytes());
        out.extend_from_slice(part);
        out.extend_from_slice(b"\r\n");
    }
    out
}

#[derive(Debug, PartialEq)]
pub enum Reply {
    Integer(i64),
    Ok,
    Null,
    Error,
}

/// Only the bounded replies used by AUTH/EVAL are accepted. RESP arrays and
/// unexpected bulk strings are errors; never allocate using a server length.
pub fn reply(input: &[u8]) -> Result<Option<(Reply, usize)>, &'static str> {
    if input.len() > 1024 {
        return Err("oversized Redis reply");
    }
    let Some(end) = input.windows(2).position(|p| p == b"\r\n") else {
        return Ok(None);
    };
    let line = &input[..end];
    let parsed = if line == b"+OK" {
        Reply::Ok
    } else if line == b"$-1" {
        Reply::Null
    } else if line.first() == Some(&b'-') {
        Reply::Error
    } else if line.first() == Some(&b':') {
        let value = std::str::from_utf8(&line[1..])
            .map_err(|_| "invalid Redis integer")?
            .parse()
            .map_err(|_| "invalid Redis integer")?;
        Reply::Integer(value)
    } else {
        return Err("unexpected Redis reply");
    };
    Ok(Some((parsed, end + 2)))
}
