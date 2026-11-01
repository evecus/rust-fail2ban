//! Proxy namespace (`silkns`) ownership, following honk's lifecycle:
//! a throwaway thread unshares a fresh network namespace and hands the ns
//! fd back to the process; every later entry uses setns(2) under a mutex.
//! A best-effort bind mount at /run/netns/<name> lets `ip -n` manage links.

use anyhow::{Context, Result};
use libc::{CLONE_NEWNET, MSG_CMSG_CLOEXEC};
use nix::sys::socket::{
    ControlMessage, ControlMessageOwned, MsgFlags, SockProtocol, UnixAddr, recvmsg, sendmsg,
};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::{Mutex, OnceLock};

static SILKNS: OnceLock<OwnedFd> = OnceLock::new();
static ENTER_LOCK: Mutex<()> = Mutex::new(());

pub const NETNS_NAME: &str = "silkns";

/// A fresh fd referring to the proxy namespace (for aya `SkLookup::attach`).
pub fn silkns_fd() -> Result<OwnedFd> {
    let ns = SILKNS.get().context("silkns not created")?;
    Ok(ns.try_clone()?)
}

/// Create the proxy namespace and retain its fd for the process lifetime.
pub fn create_silkns() -> Result<()> {
    // A previous run may have pinned a stale netns via /run/netns. Drop it
    // so this run operates on a fresh namespace.
    let _ = run_cmd(&["ip", "netns", "del", NETNS_NAME]);
    let (a, b) = nix::sys::socket::socketpair(
        nix::sys::socket::AddressFamily::Unix,
        nix::sys::socket::SockType::Stream,
        None::<SockProtocol>,
        nix::sys::socket::SockFlag::empty(),
    )?;
    let a = a.as_raw_fd();
    let handle = std::thread::spawn(move || {
        // Isolate the unshare on a throwaway thread; the main process stays
        // in the host namespace.
        let rc = unsafe { libc::unshare(CLONE_NEWNET) };
        if rc != 0 {
            anyhow::bail!("unshare(CLONE_NEWNET): {}", std::io::Error::last_os_error());
        }
        let ns_path = std::path::Path::new("/proc/thread-self/ns/net");
        let fd = std::fs::File::open(ns_path).context("open thread-self ns/net")?;
        // Send the fd over SCM_RIGHTS. A payload byte is required: a
        // zero-length send on a stream socket is a no-op and the fd
        // would never be delivered.
        let fd = fd.as_raw_fd();
        sendmsg::<UnixAddr>(
            b.as_raw_fd(),
            &[std::io::IoSlice::new(&[1u8])],
            &[ControlMessage::ScmRights(&[fd])],
            MsgFlags::empty(),
            None,
        )?;
        anyhow::Ok(())
    });
    handle
        .join()
        .map_err(|_| anyhow::anyhow!("unshare thread panicked"))??;

    // Receive the fd. The control buffer MUST be allocated: passing None
    // gives msg_control = NULL and SCM_RIGHTS is truncated away (ENOBUFS).
    let mut buf = [0u8; 8];
    let mut iov = [std::io::IoSliceMut::new(&mut buf)];
    let mut cmsg_buf = [0u8; 64];
    let msg = recvmsg::<UnixAddr>(
        a,
        &mut iov,
        Some(&mut cmsg_buf),
        MsgFlags::from_bits_truncate(MSG_CMSG_CLOEXEC),
    )
    .context("recvmsg scm_rights")?;
    let fd = match msg.cmsgs().context("cmsgs")?.next() {
        Some(ControlMessageOwned::ScmRights(fds)) => fds.first().copied(),
        _ => None,
    }
    .context("no fd received")?;

    let ns = unsafe { OwnedFd::from_raw_fd(fd) };
    SILKNS.set(ns).ok().context("silkns already created")?;

    // Best-effort bind mount for `ip -n` tooling; not required at runtime.
    let _ = bind_mount_netns();
    Ok(())
}

fn bind_mount_netns() -> Result<()> {
    let dir = std::path::Path::new("/run/netns");
    std::fs::create_dir_all(dir).ok();
    let target = dir.join(NETNS_NAME);
    if target.exists() {
        std::fs::remove_file(&target).ok();
    }
    std::fs::File::create(&target)?;
    let ns = SILKNS.get().context("silkns")?;
    let source = format!("/proc/self/fd/{}", ns.as_raw_fd());
    let src_c = std::ffi::CString::new(source)?;
    let tgt_c = std::ffi::CString::new(target.as_os_str().as_encoded_bytes())?;
    let rc = unsafe {
        libc::mount(
            src_c.as_ptr(),
            tgt_c.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        anyhow::bail!(
            "bind mount netns failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

/// Run `f` inside `silkns`, restoring the caller's namespace on all paths.
/// Never call this around an `.await` point: setns(2) is per-thread.
pub fn with_silkns<T>(f: impl FnOnce() -> Result<T>) -> Result<T> {
    let ns = SILKNS.get().context("silkns not created")?.as_raw_fd();
    let _guard = ENTER_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let saved = open_current_ns()?;
    let restore = |fd: &OwnedFd| {
        let rc = unsafe { libc::setns(fd.as_raw_fd(), CLONE_NEWNET) };
        rc == 0
    };
    let rc = unsafe { libc::setns(ns, CLONE_NEWNET) };
    if rc != 0 {
        anyhow::bail!("setns silkns: {}", std::io::Error::last_os_error());
    }
    let out = f();
    if !restore(&saved) {
        tracing::error!("failed to restore host netns; aborting");
        std::process::abort();
    }
    out
}

fn open_current_ns() -> Result<OwnedFd> {
    let fd = std::fs::File::open("/proc/thread-self/ns/net").context("open current ns")?;
    Ok(fd.into())
}

/// Run an `ip`/`sysctl` command and require success.
pub fn run_cmd(args: &[&str]) -> Result<()> {
    tracing::debug!(cmd = %args.join(" "), "exec");
    let out = std::process::Command::new(args[0])
        .args(&args[1..])
        .output()
        .with_context(|| format!("spawn {}", args[0]))?;
    if !out.status.success() {
        anyhow::bail!(
            "`{}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

/// Run `ip -n silkns ...` inside the proxy namespace.
pub fn run_ip_netns(args: &[&str]) -> Result<()> {
    let mut full: Vec<&str> = vec!["ip", "-n", NETNS_NAME];
    full.extend_from_slice(args);
    run_cmd(&full)
}

/// Best-effort teardown on exit: detach TC clsact from the captured
/// interfaces (netlink-attached filters survive the process), delete the
/// veth bridge and the proxy namespace. Errors are logged, not fatal.
pub fn cleanup(lan: Option<&str>, wan: Option<&str>, proxy_link: &str) {
    for ifc in [lan, wan, Some(proxy_link)].into_iter().flatten() {
        if let Err(e) = run_cmd(&["tc", "qdisc", "del", "dev", ifc, "clsact"]) {
            tracing::debug!("cleanup tc {ifc}: {e:#}");
        }
    }
    if let Err(e) = run_cmd(&["ip", "link", "del", proxy_link]) {
        tracing::debug!("cleanup link {proxy_link}: {e:#}");
    }
    if let Err(e) = run_cmd(&["ip", "netns", "del", NETNS_NAME]) {
        tracing::debug!("cleanup netns: {e:#}");
    }
}
