//! The small HTTP surface the e2e walks nginx with, over `ureq` 3.
//!
//! The assertions care about three outcomes and need to tell them apart: a
//! response below 400, a response at or above 400 (still carrying headers and
//! a body worth inspecting), and no response at all (`deny:444`, startup).
//! `ureq` 3 reports an error status without the response, so statuses are
//! taken as plain responses here and sorted into [`Error::Status`] by hand.

use std::sync::OnceLock;
use std::time::Duration;

use ureq::http;

#[derive(Clone)]
pub struct Agent(ureq::Agent);

impl Agent {
    /// `timeout` bounds the whole call; `follow_redirects: false` hands back a
    /// 3xx as it arrived.
    pub fn new(timeout: Option<Duration>, follow_redirects: bool) -> Self {
        let mut config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(timeout);
        if !follow_redirects {
            config = config.max_redirects(0);
        }
        Self(config.build().new_agent())
    }

    pub fn get(&self, url: &str) -> Request {
        self.request("GET", url)
    }

    pub fn request(&self, method: &str, url: &str) -> Request {
        Request {
            agent: self.0.clone(),
            builder: http::Request::builder().method(method).uri(url),
        }
    }
}

fn shared() -> &'static Agent {
    static AGENT: OnceLock<Agent> = OnceLock::new();
    AGENT.get_or_init(|| Agent::new(None, true))
}

pub fn get(url: &str) -> Request {
    shared().get(url)
}

pub fn post(url: &str) -> Request {
    shared().request("POST", url)
}

pub struct Request {
    agent: ureq::Agent,
    builder: http::request::Builder,
}

impl Request {
    pub fn set(mut self, name: &str, value: &str) -> Self {
        self.builder = self.builder.header(name, value);
        self
    }

    pub fn call(self) -> Result<Response, Error> {
        let request = self.builder.body(()).map_err(Error::transport)?;
        finish(self.agent.run(request))
    }

    pub fn send_string(self, body: &str) -> Result<Response, Error> {
        let request = self.builder.body(body.to_owned()).map_err(Error::transport)?;
        finish(self.agent.run(request))
    }

    pub fn send_json(self, body: serde_json::Value) -> Result<Response, Error> {
        self.set("Content-Type", "application/json")
            .send_string(&body.to_string())
    }
}

fn finish(result: Result<http::Response<ureq::Body>, ureq::Error>) -> Result<Response, Error> {
    let (parts, mut body) = result.map_err(Error::transport)?.into_parts();
    let body = body.read_to_vec().map_err(Error::transport)?;
    let response = Response {
        status: parts.status.as_u16(),
        headers: parts.headers,
        body,
    };
    if response.status >= 400 {
        Err(Error::Status(response.status, response))
    } else {
        Ok(response)
    }
}

pub struct Response {
    status: u16,
    headers: http::HeaderMap,
    body: Vec<u8>,
}

impl Response {
    pub fn status(&self) -> u16 {
        self.status
    }

    /// The first value of a header, if it is text.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name)?.to_str().ok()
    }

    pub fn into_string(self) -> Result<String, std::string::FromUtf8Error> {
        String::from_utf8(self.body)
    }

    pub fn into_json<T: serde::de::DeserializeOwned>(self) -> serde_json::Result<T> {
        serde_json::from_slice(&self.body)
    }
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Response({})", self.status)
    }
}

#[derive(Debug)]
pub enum Error {
    /// nginx answered with a status of 400 or above.
    Status(u16, Response),
    /// No usable response: refused, reset, closed early or timed out.
    Transport(String),
}

impl Error {
    fn transport(error: impl std::fmt::Display) -> Self {
        Error::Transport(error.to_string())
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Status(status, _) => write!(f, "status {status}"),
            Error::Transport(error) => write!(f, "{error}"),
        }
    }
}
