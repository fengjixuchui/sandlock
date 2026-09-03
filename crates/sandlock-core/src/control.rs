//! Per-sandbox control socket for introspection.
//!
//! Every sandbox (CLI, Python SDK, embedded) binds one abstract Unix
//! stream socket named `\0sandlock/<uid>/<name>` from the supervisor
//! process before the child is released. Abstract names live in the
//! kernel, not the filesystem: bind on a taken name fails, so the name is
//! the UID-wide sandbox mutex; the name vanishes with the process, so
//! nothing is ever stale; `/proc/net/unix` lists them, so `sandlock ps`
//! needs no registry on disk; and a nested sandlock needs no writable
//! directory from the outer policy, only permission to create a socket.
//!
//! Abstract names carry no permission bits, so the server checks
//! SO_PEERCRED and closes any connection from another uid.
//!
//! ## Wire protocol
//!
//! 4-byte big-endian length prefix, then UTF-8 JSON.  One request per
//! connection.
//!
//! Request:
//! ```json
//! {"v": 1, "verb": "info", "args": {}}
//! ```
//!
//! Response:
//! ```json
//! {"v": 1, "ok": true, "data": {"child_pid": 1234, "supervisor_pid": 1233, "mode": null}}
//! ```
//! or
//! ```json
//! {"v": 1, "ok": false, "err": "..."}
//! ```
//!
//! Verbs: `info` (pids and mode), `config` (effective policy as
//! `ProfileInput`), `ports` (virtual to real port map).

use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixListener};
use std::sync::Arc;

use crate::sandbox::Sandbox;
use crate::seccomp::ctx::SupervisorCtx;

// ============================================================
// Socket address
// ============================================================

/// Bytes after the leading NUL of the abstract name.
pub(crate) fn socket_name(uid: u32, name: &str) -> Vec<u8> {
    format!("sandlock/{uid}/{name}").into_bytes()
}

fn socket_addr(name: &str) -> std::io::Result<SocketAddr> {
    let uid = unsafe { libc::getuid() };
    SocketAddr::from_abstract_name(socket_name(uid, name))
}

/// Bind the sandbox's control socket. `AddrInUse` means a live sandbox of
/// this uid already owns the name.
pub(crate) fn bind_control_socket(name: &str) -> std::io::Result<UnixListener> {
    UnixListener::bind_addr(&socket_addr(name)?)
}

// ============================================================
// Control loop, spawned as a dedicated tokio task
// ============================================================

/// What the `info` verb reports: everything `sandlock ps` and `kill` need.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct SandboxInfo {
    pub child_pid: i32,
    pub supervisor_pid: i32,
    pub mode: Option<String>,
}

/// Spawn the control-loop task. `ctx` is `None` for sandboxes without a
/// seccomp-notify supervisor (`--no-supervisor`, nested); those still
/// answer `info` and the static `config`, and report no ports.
pub(crate) fn spawn_control_loop(
    listener: UnixListener,
    ctx: Option<Arc<SupervisorCtx>>,
    sandbox: Sandbox,
    info: SandboxInfo,
) -> tokio::task::JoinHandle<()> {
    // Mutex only to satisfy Sync: Sandbox carries a Box<dyn FnOnce> slot
    // even though this clone's is None.
    let sandbox = Arc::new(tokio::sync::Mutex::new(sandbox));
    tokio::spawn(async move {
        control_loop(listener, ctx, sandbox, info, unsafe { libc::getuid() }).await;
    })
}

fn peer_uid(fd: std::os::unix::io::RawFd) -> Option<u32> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    (rc == 0).then_some(cred.uid)
}

/// Accept one connection at a time and serve one request per connection.
/// `my_uid` is a parameter so a test can prove the refusal path without a
/// second uid. The timeout keeps one stalled client from wedging
/// introspection, which kill now depends on.
async fn control_loop(
    listener: UnixListener,
    ctx: Option<Arc<SupervisorCtx>>,
    sandbox: Arc<tokio::sync::Mutex<Sandbox>>,
    info: SandboxInfo,
    my_uid: u32,
) {
    use std::os::unix::io::AsRawFd;
    listener.set_nonblocking(true).ok();
    let listener = match tokio::net::UnixListener::from_std(listener) {
        Ok(l) => l,
        Err(_) => return,
    };

    loop {
        let (stream, _addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(_) => return,
        };
        // Abstract names have no permission bits, so this is the only gate.
        if peer_uid(stream.as_raw_fd()) != Some(my_uid) {
            continue;
        }
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            serve_one(stream, ctx.as_ref(), &sandbox, &info),
        )
        .await;
    }
}

// ============================================================
// Request handling
// ============================================================

#[derive(serde::Deserialize)]
struct ControlRequest {
    v: u32,
    verb: String,
    #[serde(default)]
    #[allow(dead_code)]
    args: serde_json::Value,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct ControlResponse {
    pub v: u32,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub err: Option<String>,
}

async fn serve_one(
    stream: tokio::net::UnixStream,
    ctx: Option<&Arc<SupervisorCtx>>,
    sandbox: &Arc<tokio::sync::Mutex<Sandbox>>,
    info: &SandboxInfo,
) {
    use tokio::io::AsyncReadExt;

    let mut stream = stream;
    let mut len_buf = [0u8; 4];
    if stream.read_exact(&mut len_buf).await.is_err() {
        return;
    }
    let body_len = u32::from_be_bytes(len_buf) as usize;
    // Reject unreasonable sizes.
    if body_len > 65536 {
        return;
    }
    let mut body = vec![0u8; body_len];
    if stream.read_exact(&mut body).await.is_err() {
        return;
    }

    let req: ControlRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            let resp = ControlResponse {
                v: 1,
                ok: false,
                data: None,
                err: Some(format!("parse error: {}", e)),
            };
            let _ = write_response(&mut stream, &resp).await;
            return;
        }
    };

    if req.v != 1 {
        let resp = ControlResponse {
            v: 1,
            ok: false,
            data: None,
            err: Some(format!("unsupported protocol version: {}", req.v)),
        };
        let _ = write_response(&mut stream, &resp).await;
        return;
    }

    match req.verb.as_str() {
        "info" => handle_info(&mut stream, info).await,
        "config" => handle_config(&mut stream, ctx, sandbox).await,
        "ports" => handle_ports(&mut stream, ctx).await,
        _ => {
            let resp = ControlResponse {
                v: 1,
                ok: false,
                data: None,
                err: Some(format!("unknown verb: {}", req.verb)),
            };
            let _ = write_response(&mut stream, &resp).await;
        }
    }
}

async fn handle_info(stream: &mut tokio::net::UnixStream, info: &SandboxInfo) {
    let resp = match serde_json::to_value(info) {
        Ok(data) => ControlResponse { v: 1, ok: true, data: Some(data), err: None },
        Err(e) => ControlResponse {
            v: 1,
            ok: false,
            data: None,
            err: Some(format!("serialize error: {}", e)),
        },
    };
    let _ = write_response(stream, &resp).await;
}

async fn handle_config(
    stream: &mut tokio::net::UnixStream,
    ctx: Option<&Arc<SupervisorCtx>>,
    sandbox: &Arc<tokio::sync::Mutex<Sandbox>>,
) {
    let dynamic_denied: Vec<String> = match ctx {
        Some(ctx) => ctx.policy_fn.lock().await.denied.denied_paths(),
        None => Vec::new(),
    };

    // Build the effective profile.
    let sb = sandbox.lock().await;
    let profile = crate::profile::sandbox_to_profile(&sb, &dynamic_denied);

    // Emit JSON.  Wrap in a "policy" key so the top-level response is
    // structured; the data field is the full ProfileInput.
    let data = match serde_json::to_value(&profile) {
        Ok(v) => v,
        Err(e) => {
            let resp = ControlResponse {
                v: 1,
                ok: false,
                data: None,
                err: Some(format!("serialize error: {}", e)),
            };
            let _ = write_response(stream, &resp).await;
            return;
        }
    };

    let resp = ControlResponse {
        v: 1,
        ok: true,
        data: Some(data),
        err: None,
    };
    let _ = write_response(stream, &resp).await;
}

async fn handle_ports(
    stream: &mut tokio::net::UnixStream,
    ctx: Option<&Arc<SupervisorCtx>>,
) {
    let ports: std::collections::HashMap<u16, u16> = match ctx {
        Some(ctx) => ctx.network.lock().await.port_map.virtual_to_real.clone(),
        None => Default::default(),
    };

    let data = match serde_json::to_value(&ports) {
        Ok(v) => v,
        Err(e) => {
            let resp = ControlResponse {
                v: 1,
                ok: false,
                data: None,
                err: Some(format!("serialize error: {}", e)),
            };
            let _ = write_response(stream, &resp).await;
            return;
        }
    };

    let resp = ControlResponse {
        v: 1,
        ok: true,
        data: Some(data),
        err: None,
    };
    let _ = write_response(stream, &resp).await;
}

/// Write a length-prefixed JSON response.  Rejects bodies over 64 KB
/// (mirrors the client-side cap in `send_control_request`).
async fn write_response(
    stream: &mut tokio::net::UnixStream,
    resp: &ControlResponse,
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    const MAX_RESPONSE_BYTES: usize = 65536;

    let body = serde_json::to_vec(resp).unwrap_or_else(|_| {
        serde_json::to_vec(&ControlResponse {
            v: 1,
            ok: false,
            data: None,
            err: Some("internal error".to_string()),
        })
        .unwrap_or_default()
    });

    // Cap oversized responses on the server side too.
    let body = if body.len() > MAX_RESPONSE_BYTES {
        serde_json::to_vec(&ControlResponse {
            v: 1,
            ok: false,
            data: None,
            err: Some(format!(
                "response too large ({} bytes, max {})",
                body.len(),
                MAX_RESPONSE_BYTES
            )),
        })
        .unwrap_or_default()
    } else {
        body
    };

    let len = (body.len() as u32).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(&body).await?;
    Ok(())
}

// ============================================================
// Discovery
// ============================================================

/// Names of every listening control socket belonging to `uid`, parsed
/// from `/proc/net/unix` text. Columns: Num RefCount Protocol Flags Type
/// St Inode Path; Flags 00010000 is __SO_ACCEPTCON, a listening socket.
pub(crate) fn parse_proc_net_unix(text: &str, uid: u32) -> Vec<String> {
    let prefix = format!("@sandlock/{uid}/");
    let mut names: Vec<String> = text
        .lines()
        .skip(1)
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let flags = fields.nth(3)?;
            let path = fields.nth(3)?;
            if flags != "00010000" {
                return None;
            }
            path.strip_prefix(&prefix).map(str::to_string)
        })
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Names of the caller's live sandboxes, sorted.
pub fn list_sandboxes() -> std::io::Result<Vec<String>> {
    let text = std::fs::read_to_string("/proc/net/unix")?;
    Ok(parse_proc_net_unix(&text, unsafe { libc::getuid() }))
}

// ============================================================
// Client helpers — used by sandlock-cli to talk to the socket
// ============================================================

fn unresponsive(name: &str, e: std::io::Error) -> String {
    match e.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
            format!("sandbox '{}' is unresponsive", name)
        }
        _ => format!("read from sandbox '{}': {}", name, e),
    }
}

/// Send a request to a sandbox's control socket and return the response.
pub fn send_control_request(
    name: &str,
    verb: &str,
    args: serde_json::Value,
) -> Result<ControlResponse, String> {
    send_control_request_as(name, verb, args, unsafe { libc::getuid() })
}

/// `my_uid` is a parameter so a test can prove the refusal without a
/// second uid. SO_PEERCRED on a connected stream reports the listener's
/// credentials, so a name squatted by another user is rejected here.
fn send_control_request_as(
    name: &str,
    verb: &str,
    args: serde_json::Value,
    my_uid: u32,
) -> Result<ControlResponse, String> {
    use std::io::{Read, Write};
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::UnixStream;

    let addr = socket_addr(name).map_err(|e| format!("socket address for '{}': {}", name, e))?;
    let mut stream = match UnixStream::connect_addr(&addr) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            return Err(format!("no sandbox named '{}'", name));
        }
        Err(e) => return Err(format!("connect to sandbox '{}': {}", name, e)),
    };
    if peer_uid(stream.as_raw_fd()) != Some(my_uid) {
        return Err(format!("socket for '{}' is owned by another user", name));
    }

    // Set a 2-second timeout on reads so a wedged supervisor does not
    // block the CLI forever.
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .map_err(|e| format!("set_read_timeout: {}", e))?;
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(2)))
        .map_err(|e| format!("set_write_timeout: {}", e))?;

    let req = serde_json::json!({
        "v": 1,
        "verb": verb,
        "args": args,
    });
    let body = serde_json::to_vec(&req)
        .map_err(|e| format!("serialize request: {}", e))?;

    let len = (body.len() as u32).to_be_bytes();
    stream.write_all(&len).map_err(|e| format!("write len: {}", e))?;
    stream.write_all(&body).map_err(|e| format!("write body: {}", e))?;

    // Read response.
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).map_err(|e| unresponsive(name, e))?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    if resp_len > 65536 {
        return Err("response too large".to_string());
    }
    let mut resp_body = vec![0u8; resp_len];
    stream.read_exact(&mut resp_body).map_err(|e| unresponsive(name, e))?;

    serde_json::from_slice(&resp_body)
        .map_err(|e| format!("parse response: {}", e))
}

/// Ask a sandbox for its pids and mode.
pub fn sandbox_info(name: &str) -> Result<SandboxInfo, String> {
    let resp = send_control_request(name, "info", serde_json::Value::Object(Default::default()))?;
    if !resp.ok {
        return Err(resp.err.unwrap_or_else(|| "info failed".into()));
    }
    let data = resp.data.ok_or_else(|| "empty info response".to_string())?;
    serde_json::from_value(data).map_err(|e| format!("parse info response: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn longest_name_fits_sun_path() {
        let name = "x".repeat(64);
        // Leading NUL plus the name must fit the kernel's 108-byte sun_path.
        assert!(socket_name(u32::MAX, &name).len() < 108);
    }

    #[test]
    fn parses_listening_sockets_for_uid_only() {
        let text = "Num RefCount Protocol Flags Type St Inode Path\n\
            0000000000000000: 00000002 00000000 00010000 0001 01 11628860 @sandlock/1000/alpha\n\
            0000000000000000: 00000003 00000000 00000000 0001 03 11628861 @sandlock/1000/alpha\n\
            0000000000000000: 00000002 00000000 00010000 0001 01 11628862 @sandlock/1001/other\n\
            0000000000000000: 00000002 00000000 00010000 0001 01 11628863 /run/user/1000/bus\n\
            0000000000000000: 00000002 00000000 00010000 0001 01 11628864 @sandlock/1000/beta\n";
        assert_eq!(parse_proc_net_unix(text, 1000), vec!["alpha", "beta"]);
        assert_eq!(parse_proc_net_unix(text, 1001), vec!["other"]);
    }

    #[test]
    fn bind_is_the_name_mutex_and_listing_follows_the_listener() {
        // Unique name: sandbox names are uid-wide, never reuse a fixed one.
        let name = format!("test-ctrl-unit-{}", std::process::id());
        let listener = bind_control_socket(&name).unwrap();
        assert!(list_sandboxes().unwrap().contains(&name));
        let err = bind_control_socket(&name).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
        drop(listener);
        assert!(!list_sandboxes().unwrap().contains(&name));
    }

    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    fn test_sandbox() -> Sandbox {
        Sandbox::builder().fs_read("/usr").build().unwrap()
    }

    fn info() -> SandboxInfo {
        SandboxInfo { child_pid: 4242, supervisor_pid: 4241, mode: None }
    }

    /// Bind a listener for `name`, run the control loop on it with
    /// `expected_uid`, and return the task handle.
    fn serve(name: &str, expected_uid: u32) -> tokio::task::JoinHandle<()> {
        let listener = bind_control_socket(name).unwrap();
        let sandbox = Arc::new(tokio::sync::Mutex::new(test_sandbox()));
        tokio::spawn(control_loop(listener, None, sandbox, info(), expected_uid))
    }

    /// Connect as ourselves, send an info request, and return what the
    /// server sent back (empty on a silent close).
    fn raw_info_request(name: &str) -> Vec<u8> {
        let mut s = UnixStream::connect_addr(&socket_addr(name).unwrap()).unwrap();
        let body = br#"{"v":1,"verb":"info","args":{}}"#;
        s.write_all(&(body.len() as u32).to_be_bytes()).unwrap();
        s.write_all(body).unwrap();
        s.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        out
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn server_answers_its_own_uid() {
        let name = format!("test-ctrl-own-{}", std::process::id());
        let task = serve(&name, unsafe { libc::getuid() });
        let out = tokio::task::spawn_blocking(move || raw_info_request(&name)).await.unwrap();
        task.abort();
        assert!(out.len() > 4, "expected a response, got {} bytes", out.len());
        let resp: ControlResponse = serde_json::from_slice(&out[4..]).unwrap();
        assert!(resp.ok);
        let got: SandboxInfo = serde_json::from_value(resp.data.unwrap()).unwrap();
        assert_eq!((got.child_pid, got.supervisor_pid), (4242, 4241));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn server_closes_on_another_uid_without_answering() {
        let name = format!("test-ctrl-foreign-{}", std::process::id());
        let task = serve(&name, unsafe { libc::getuid() }.wrapping_add(1));
        let out = tokio::task::spawn_blocking(move || raw_info_request(&name)).await.unwrap();
        task.abort();
        assert!(out.is_empty(), "another uid must get no bytes, got {:?}", out);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn client_refuses_a_listener_owned_by_another_uid() {
        let name = format!("test-ctrl-squat-{}", std::process::id());
        let task = serve(&name, unsafe { libc::getuid() });
        let expect = unsafe { libc::getuid() }.wrapping_add(1);
        let n = name.clone();
        let err = tokio::task::spawn_blocking(move || {
            send_control_request_as(&n, "info", serde_json::Value::Object(Default::default()), expect)
                .unwrap_err()
        })
        .await
        .unwrap();
        task.abort();
        assert!(err.contains("owned by another user"), "got: {err}");
    }

    #[test]
    fn listing_survives_a_foreign_non_utf8_name() {
        let addr = SocketAddr::from_abstract_name(b"sandlock-probe-\xff\xfe").unwrap();
        let _foreign = UnixListener::bind_addr(&addr).unwrap();
        let name = format!("test-ctrl-utf8-{}", std::process::id());
        let _ours = bind_control_socket(&name).unwrap();
        assert!(list_sandboxes().unwrap().contains(&name));
    }
}
