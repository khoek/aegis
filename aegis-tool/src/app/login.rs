use std::io::{self, ErrorKind, Read, Write};
use std::net::TcpListener;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::api::{finish_browser_login, start_browser_login};
use crate::cli::LoginArgs;
use crate::config::{now_unix, persist_user_auth_state, resolve_api_base};
use crate::ui::{self, TaskOptions, TaskVisibility};

const REMOTE_AUTH_FORMAT_VERSION: u8 = 1;
const SUCCESS_HTML: &str = "<!doctype html><html><head><meta charset=\"utf-8\"><title>aegis login complete</title><style>body{font-family:ui-sans-serif,system-ui,sans-serif;background:#101418;color:#eaf1f6;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}main{max-width:34rem;padding:2rem 2.5rem;border:1px solid #29404f;border-radius:18px;background:#152029;box-shadow:0 20px 60px rgba(0,0,0,.25)}h1{margin:0 0 .75rem;font-size:1.5rem}p{margin:.5rem 0;line-height:1.5;color:#b9cad4}code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.95em}</style></head><body><main><h1><code>aegis</code> login complete</h1><p>You can close this browser window and return to the terminal.</p></main></body></html>";
const ERROR_HTML: &str = "<!doctype html><html><head><meta charset=\"utf-8\"><title>aegis login failed</title><style>body{font-family:ui-sans-serif,system-ui,sans-serif;background:#151110;color:#f5ebe6;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}main{max-width:34rem;padding:2rem 2.5rem;border:1px solid #5a2a1f;border-radius:18px;background:#221613;box-shadow:0 20px 60px rgba(0,0,0,.3)}h1{margin:0 0 .75rem;font-size:1.5rem}p{margin:.5rem 0;line-height:1.5;color:#e7c1b4}code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.95em}</style></head><body><main><h1><code>aegis</code> login failed</h1><p>The terminal has the detailed error. You can close this browser window.</p></main></body></html>";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RemoteAuthRequest {
    version: u8,
    authorization_url: String,
    callback_url: String,
    state: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RemoteAuthResponse {
    version: u8,
    code: String,
    state: String,
}

pub(super) struct BrowserLogin<'a> {
    api_base_override: Option<&'a str>,
    args: &'a LoginArgs,
}

impl<'a> BrowserLogin<'a> {
    pub(super) fn from_cli(api_base_override: Option<&'a str>, args: &'a LoginArgs) -> Self {
        Self {
            api_base_override,
            args,
        }
    }

    pub(super) fn run(&self) -> Result<i32> {
        if let Some(request) = self.args.remote_auth_relay.as_deref() {
            return relay_remote_auth(request, self.args.wait_timeout_secs);
        }

        let installed_agent_api_base = crate::api::installed_agent_api_base()?;
        let api_base =
            resolve_api_base(self.api_base_override, installed_agent_api_base.as_deref())?;

        if self.args.remote_auth {
            return self.run_remote_auth(&api_base);
        }

        self.run_local_browser_auth(&api_base)
    }

    fn run_local_browser_auth(&self, api_base: &str) -> Result<i32> {
        self.complete(api_base, false)
    }

    fn run_remote_auth(&self, api_base: &str) -> Result<i32> {
        self.complete(api_base, true)
    }

    fn complete(&self, api_base: &str, remote: bool) -> Result<i32> {
        let proof = browser_proof(
            api_base,
            remote,
            Duration::from_secs(self.args.wait_timeout_secs),
        )?;
        proof.finish(api_base)?;
        Ok(0)
    }
}

pub struct BrowserProof {
    pub code: String,
    pub verifier: String,
    pub callback: Url,
}

impl BrowserProof {
    pub fn finish(self, api_base: &str) -> Result<()> {
        let exchange = ui::task(TaskOptions {
            label: "Completing sign-in".into(),
            deadline: Some(Duration::from_secs(30)),
            ..Default::default()
        })?;
        let auth = finish_browser_login(
            api_base,
            &self.callback,
            &self.code,
            &self.verifier,
            now_unix(),
        )?;
        persist_user_auth_state(&auth)?;
        exchange.finish(format!("Logged in as {}", auth.principal));
        Ok(())
    }
}

pub fn browser_proof(api_base: &str, remote: bool, timeout: Duration) -> Result<BrowserProof> {
    ui::require_interactive("Browser sign-in requires an interactive terminal")?;
    let prepare = ui::task(TaskOptions {
        label: "Preparing browser sign-in".into(),
        ..Default::default()
    })?;
    let listener = CallbackListener::bind()?;
    let callback = listener.callback_url().clone();
    let login = start_browser_login(api_base, &callback)?;
    prepare.finish_and_clear();
    let started = Instant::now();
    let (code, state) = if remote {
        let request = encode_remote_auth_request(&RemoteAuthRequest {
            version: REMOTE_AUTH_FORMAT_VERSION,
            authorization_url: login.authorization_url.to_string(),
            callback_url: callback.to_string(),
            state: login.state.clone(),
        })?;
        ui::stage(&format!(
            "On the machine with a browser, run:\n  aegis manage login --remote-auth-relay {request}"
        ));
        ui::detail(&format!(
            "Waiting for your relay response until {} UTC. Complete the relay promptly after browser authorization.",
            time::OffsetDateTime::now_utc()
                + time::Duration::seconds(timeout.as_secs().try_into()?)
        ));
        let response = ui::suspend(prompt_remote_auth_response)?;
        anyhow::ensure!(
            started.elapsed() < timeout,
            "remote sign-in attempt expired; start a new attempt"
        );
        let response = decode_remote_auth_response(&response)?;
        (response.code, response.state)
    } else {
        ui::maybe_open_browser(login.authorization_url.as_str());
        print_authorization_url(&login.authorization_url);
        let wait = ui::task(TaskOptions {
            label: "Waiting for browser authorization".into(),
            deadline: Some(timeout),
            visibility: TaskVisibility::Immediate,
            ..Default::default()
        })?;
        let response = listener.wait(timeout)?;
        wait.finish_and_clear();
        (response.code, response.state)
    };
    anyhow::ensure!(
        state == login.state,
        "OAuth callback returned the wrong state"
    );
    Ok(BrowserProof {
        code,
        verifier: login.pkce_verifier,
        callback,
    })
}

fn relay_remote_auth(encoded_request: &str, wait_timeout_secs: u64) -> Result<i32> {
    ui::require_interactive(
        "`aegis manage login --remote-auth-relay` requires an interactive terminal",
    )?;
    let request = decode_remote_auth_request(encoded_request)?;
    let (authorization_url, callback_url) = validate_remote_auth_request(&request)?;
    let listener = CallbackListener::bind_callback(&callback_url)?;

    ui::current().info("Opening browser for remote OAuth login");
    ui::maybe_open_browser(authorization_url.as_str());
    print_authorization_url(&authorization_url);

    let callback_timeout = Duration::from_secs(wait_timeout_secs);
    let wait = ui::task(TaskOptions {
        label: "Waiting for browser authorization".to_string(),
        deadline: Some(callback_timeout),
        visibility: TaskVisibility::Immediate,
        ..TaskOptions::default()
    })?;
    let callback = listener.wait(callback_timeout)?;
    wait.finish("Browser authorization completed");
    if callback.state != request.state {
        bail!("oauth callback returned the wrong state");
    }

    let response = encode_remote_auth_response(&RemoteAuthResponse {
        version: REMOTE_AUTH_FORMAT_VERSION,
        code: callback.code,
        state: callback.state,
    })?;
    ui::stage("Paste this response into the waiting remote prompt:");
    println!("{response}");
    ui::success("Remote authentication response ready.");
    Ok(0)
}

fn print_authorization_url(url: &Url) {
    ui::stage(&format!("Authorization URL: {url}"));
}

fn prompt_remote_auth_response() -> Result<String> {
    eprint!("Paste the remote authentication response: ");
    io::stderr()
        .flush()
        .context("failed to flush remote authentication prompt")?;
    let mut response = String::new();
    io::stdin()
        .read_line(&mut response)
        .context("failed to read remote authentication response")?;
    let response = response.trim();
    if response.is_empty() {
        bail!("remote authentication response must not be empty");
    }
    Ok(response.to_string())
}

fn encode_remote_auth_request(request: &RemoteAuthRequest) -> Result<String> {
    encode_remote_auth_value(request, "request")
}

fn encode_remote_auth_response(response: &RemoteAuthResponse) -> Result<String> {
    encode_remote_auth_value(response, "response")
}

fn encode_remote_auth_value<T: Serialize>(value: &T, kind: &str) -> Result<String> {
    let json = serde_json::to_vec(value)
        .with_context(|| format!("failed to encode remote authentication {kind}"))?;
    Ok(URL_SAFE_NO_PAD.encode(json))
}

fn decode_remote_auth_request(encoded: &str) -> Result<RemoteAuthRequest> {
    let request: RemoteAuthRequest = decode_remote_auth_value(encoded, "request")?;
    if request.version != REMOTE_AUTH_FORMAT_VERSION {
        bail!(
            "unsupported remote authentication request version {}",
            request.version
        );
    }
    Ok(request)
}

fn decode_remote_auth_response(encoded: &str) -> Result<RemoteAuthResponse> {
    let response: RemoteAuthResponse = decode_remote_auth_value(encoded, "response")?;
    if response.version != REMOTE_AUTH_FORMAT_VERSION {
        bail!(
            "unsupported remote authentication response version {}",
            response.version
        );
    }
    if response.code.trim().is_empty() || response.state.trim().is_empty() {
        bail!("remote authentication response is incomplete");
    }
    Ok(response)
}

fn decode_remote_auth_value<T: for<'de> Deserialize<'de>>(encoded: &str, kind: &str) -> Result<T> {
    let json = URL_SAFE_NO_PAD
        .decode(encoded.trim())
        .with_context(|| format!("failed to decode remote authentication {kind}"))?;
    serde_json::from_slice(&json)
        .with_context(|| format!("failed to parse remote authentication {kind}"))
}

fn validate_remote_auth_request(request: &RemoteAuthRequest) -> Result<(Url, Url)> {
    let authorization_url = Url::parse(&request.authorization_url)
        .context("remote authentication request has an invalid authorization URL")?;
    validate_authorization_url(&authorization_url)?;
    let callback_url = Url::parse(&request.callback_url)
        .context("remote authentication request has an invalid callback URL")?;
    validate_callback_url(&callback_url)?;

    let redirect_uri = query_value(&authorization_url, "redirect_uri")?;
    if redirect_uri != callback_url.as_str() {
        bail!("remote authentication request callback URL does not match its authorization URL");
    }
    let state = query_value(&authorization_url, "state")?;
    if state != request.state || state.trim().is_empty() {
        bail!("remote authentication request has an inconsistent OAuth state");
    }
    Ok((authorization_url, callback_url))
}

fn validate_authorization_url(url: &Url) -> Result<()> {
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        bail!("remote authentication authorization URL contains forbidden URL components");
    }
    let secure = url.scheme() == "https";
    let loopback_http =
        url.scheme() == "http" && matches!(url.host_str(), Some("127.0.0.1" | "::1" | "localhost"));
    if !secure && !loopback_http {
        bail!("remote authentication authorization URL must use HTTPS");
    }
    Ok(())
}

fn validate_callback_url(url: &Url) -> Result<()> {
    if url.scheme() != "http"
        || url.host_str() != Some("127.0.0.1")
        || url.port().is_none()
        || url.path() != "/callback"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        bail!("remote authentication callback must be an unadorned 127.0.0.1 HTTP callback URL");
    }
    Ok(())
}

struct CallbackListener {
    listener: TcpListener,
    callback_url: Url,
}

impl CallbackListener {
    fn bind() -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .context("failed to bind local login callback listener")?;
        listener
            .set_nonblocking(true)
            .context("failed to configure local login callback listener")?;
        let callback_url = Url::parse(&format!(
            "http://127.0.0.1:{}/callback",
            listener.local_addr()?.port()
        ))
        .context("failed to build local callback url")?;
        Ok(Self {
            listener,
            callback_url,
        })
    }

    fn bind_callback(callback_url: &Url) -> Result<Self> {
        validate_callback_url(callback_url)?;
        let port = callback_url
            .port()
            .ok_or_else(|| anyhow!("remote authentication callback URL has no port"))?;
        let listener = TcpListener::bind(("127.0.0.1", port)).with_context(|| {
            format!(
                "failed to bind local remote-auth callback listener on 127.0.0.1:{port}; rerun the remote command to obtain a new request"
            )
        })?;
        listener
            .set_nonblocking(true)
            .context("failed to configure local remote-auth callback listener")?;
        Ok(Self {
            listener,
            callback_url: callback_url.clone(),
        })
    }

    fn callback_url(&self) -> &Url {
        &self.callback_url
    }

    fn wait(&self, timeout: Duration) -> Result<LoginCallback> {
        let deadline = Instant::now() + timeout;
        let mut buffer = [0u8; 8192];

        loop {
            match self.listener.accept() {
                Ok((mut stream, _)) => {
                    let bytes_read = stream
                        .read(&mut buffer)
                        .context("failed to read oauth callback request")?;
                    let request = String::from_utf8_lossy(&buffer[..bytes_read]);
                    let path = parse_http_request_path(&request)?;
                    let callback_url = Url::parse(&format!("http://127.0.0.1{path}"))
                        .context("failed to parse callback url")?;
                    if let Some(error) = query_optional_value(&callback_url, "error") {
                        let description = query_optional_value(&callback_url, "error_description")
                            .unwrap_or_default();
                        let response = html_response(ERROR_HTML);
                        let _ = stream.write_all(response.as_bytes());
                        let _ = stream.flush();
                        let detail = if description.is_empty() {
                            error
                        } else {
                            format!("{error}: {description}")
                        };
                        bail!("oauth callback reported an error: {detail}");
                    }
                    let code = query_value(&callback_url, "code")?;
                    let state = query_value(&callback_url, "state")?;

                    let response = html_response(SUCCESS_HTML);
                    stream
                        .write_all(response.as_bytes())
                        .context("failed to write oauth callback response")?;
                    stream.flush().ok();

                    return Ok(LoginCallback { code, state });
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        bail!("timed out waiting for browser login callback");
                    }
                    ui::sleep(Duration::from_millis(100))?;
                }
                Err(error) => {
                    return Err(error).context("failed waiting for browser login callback");
                }
            }
        }
    }
}

struct LoginCallback {
    code: String,
    state: String,
}

pub(super) fn parse_http_request_path(request: &str) -> Result<String> {
    let first_line = request
        .lines()
        .next()
        .ok_or_else(|| anyhow!("empty http callback request"))?;
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();
    if method != "GET" || path.is_empty() {
        bail!("unexpected oauth callback request line: {first_line}");
    }
    Ok(path.to_string())
}

fn query_value(url: &Url, name: &str) -> Result<String> {
    url.query_pairs()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
        .ok_or_else(|| anyhow!("oauth callback missing `{name}`"))
}

fn query_optional_value(url: &Url, name: &str) -> Option<String> {
    url.query_pairs()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
}

fn html_response(html: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        html.len(),
        html
    )
}

#[cfg(test)]
mod tests {
    use super::{
        REMOTE_AUTH_FORMAT_VERSION, RemoteAuthRequest, RemoteAuthResponse,
        decode_remote_auth_request, decode_remote_auth_response, encode_remote_auth_request,
        encode_remote_auth_response, validate_remote_auth_request,
    };

    #[test]
    fn remote_auth_request_round_trip_preserves_browser_handoff() {
        let request = RemoteAuthRequest {
            version: REMOTE_AUTH_FORMAT_VERSION,
            authorization_url: "https://api.example/v2/oauth/authorize?response_type=code&client_id=aegis-tool&state=state-1&code_challenge=challenge&code_challenge_method=S256&redirect_uri=http%3A%2F%2F127.0.0.1%3A43123%2Fcallback".to_string(),
            callback_url: "http://127.0.0.1:43123/callback".to_string(),
            state: "state-1".to_string(),
        };

        let encoded = encode_remote_auth_request(&request).expect("request should encode");
        assert!(!encoded.contains('='));
        let decoded = decode_remote_auth_request(&encoded).expect("request should decode");
        let (_, callback) =
            validate_remote_auth_request(&decoded).expect("request should validate");
        assert_eq!("http://127.0.0.1:43123/callback", callback.as_str());
    }

    #[test]
    fn remote_auth_response_round_trip_contains_only_code_and_state() {
        let response = RemoteAuthResponse {
            version: REMOTE_AUTH_FORMAT_VERSION,
            code: "one-time-code".to_string(),
            state: "state-1".to_string(),
        };

        let encoded = encode_remote_auth_response(&response).expect("response should encode");
        let decoded = decode_remote_auth_response(&encoded).expect("response should decode");
        assert_eq!("one-time-code", decoded.code);
        assert_eq!("state-1", decoded.state);
    }

    #[test]
    fn remote_auth_request_rejects_non_loopback_callback() {
        let request = RemoteAuthRequest {
            version: REMOTE_AUTH_FORMAT_VERSION,
            authorization_url: "https://api.example/v2/oauth/authorize?state=state-1&redirect_uri=https%3A%2F%2Fevil.example%2Fcallback".to_string(),
            callback_url: "https://evil.example/callback".to_string(),
            state: "state-1".to_string(),
        };

        validate_remote_auth_request(&request)
            .expect_err("non-loopback callbacks must be rejected");
    }
}
