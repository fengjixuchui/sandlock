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
use std::path::PathBuf;
use std::sync::Arc;

use crate::sandbox::Sandbox;
use crate::seccomp::ctx::SupervisorCtx;

// ============================================================
// Socket address
// ============================================================

/// Bytes after the leading NUL of the abstract name. Public so tests can
/// address a socket of another uid.
pub fn socket_name(uid: u32, name: &str) -> Vec<u8> {
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
// Control loop — spawned as a dedicated tokio task
// ============================================================

/// Spawn the control-loop task.  Returns immediately after spawning; the task
/// runs until the listener is closed or the supervisor shuts down.
///
/// Takes ownership of `sandbox` (moved into the task) so the config snapshot
/// lives for the lifetime of the control loop.  The sandbox clone has
/// `init_fn = None` (FnOnce can't be cloned), so the value is `Send`.
pub(crate) fn spawn_control_loop(
    listener: UnixListener,
    ctx: Arc<SupervisorCtx>,
    sandbox: Sandbox,
    dir: PathBuf,
) -> tokio::task::JoinHandle<()> {
    // Use a Mutex to satisfy Sync (Sandbox is not Sync due to the type-level
    // presence of Box<dyn FnOnce>, even though our clone has init_fn=None).
    // The control loop only reads, so a Mutex is fine.
    let sandbox = Arc::new(tokio::sync::Mutex::new(sandbox));
    tokio::spawn(async move {
        control_loop(listener, ctx, sandbox, dir).await;
    })
}

/// Accept connections on the control socket and serve one request per
/// connection (single-client-at-a-time, no concurrency).
async fn control_loop(
    listener: UnixListener,
    ctx: Arc<SupervisorCtx>,
    sandbox: Arc<tokio::sync::Mutex<Sandbox>>,
    _dir: PathBuf,
) {
    // Convert std listener to tokio.
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

        // Optional: audit peer credentials (same-UID trust boundary).
        // SO_PEERCRED is cheap and surfaces unexpected mismatches.
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let raw = stream.as_raw_fd();
            let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
            if unsafe {
                libc::getsockopt(
                    raw,
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    &mut cred as *mut _ as *mut libc::c_void,
                    &mut len,
                )
            } == 0
            {
                let my_uid = unsafe { libc::getuid() };
                if cred.uid != my_uid {
                    eprintln!(
                        "sandlock: control socket: peer uid {} != my uid {} — \
                         unexpected; dir 0700 should prevent this",
                        cred.uid, my_uid
                    );
                }
            }
        }

        // Serve one request; close after.
        serve_one(stream, &ctx, &sandbox).await;
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
    ctx: &Arc<SupervisorCtx>,
    sandbox: &Arc<tokio::sync::Mutex<Sandbox>>,
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

async fn handle_config(
    stream: &mut tokio::net::UnixStream,
    ctx: &Arc<SupervisorCtx>,
    sandbox: &Arc<tokio::sync::Mutex<Sandbox>>,
) {
    // Collect dynamic policy_fn denies.
    let dynamic_denied: Vec<String> = {
        let pfn = ctx.policy_fn.lock().await;
        pfn.denied.denied_paths()
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
    ctx: &Arc<SupervisorCtx>,
) {
    // Read the current virtual→real port map from the supervisor's
    // NetworkState.  This is the live mapping at request-time — more
    // accurate than a static registry that only refreshes on bind and
    // goes stale on SIGKILL.
    let ports: std::collections::HashMap<u16, u16> = {
        let ns = ctx.network.lock().await;
        ns.port_map.virtual_to_real.clone()
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

/// Send a request to a sandbox's control socket and return the JSON response
/// body (the `data` field, or error).
pub fn send_control_request(
    name: &str,
    verb: &str,
    args: serde_json::Value,
) -> Result<ControlResponse, String> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let dir = sandbox_dir(name);

    // Check supervisor liveness before attempting connect.  If the
    // supervisor is dead the socket is stale and connect() would fail
    // with a confusing "No such file" — give a clearer message.
    if let Some(pid) = read_supervisor_pid(&dir) {
        if unsafe { libc::kill(pid, 0) } != 0 {
            return Err(format!(
                "sandbox '{}' supervisor (PID {}) is not running",
                name, pid
            ));
        }
    }

    let sp = sock_path(&dir);
    let mut stream = UnixStream::connect(&sp)
        .map_err(|e| format!("connect to {:?}: {}", sp, e))?;

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
    stream.read_exact(&mut len_buf).map_err(|e| format!("read len: {}", e))?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    if resp_len > 65536 {
        return Err("response too large".to_string());
    }
    let mut resp_body = vec![0u8; resp_len];
    stream.read_exact(&mut resp_body).map_err(|e| format!("read body: {}", e))?;

    serde_json::from_slice(&resp_body)
        .map_err(|e| format!("parse response: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn longest_name_fits_sun_path() {
        let name = "x".repeat(64);
        // Leading NUL plus the name must fit the kernel's 108-byte sun_path.
        assert!(socket_name(u32::MAX, &name).len() + 1 <= 108);
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
}
