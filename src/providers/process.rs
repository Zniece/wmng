//! Win32 process bindings: enumeration and the two termination paths.
//!
//! Enumeration goes through the Toolhelp snapshot in v1 (the
//! `NtQuerySystemInformation` fast path is deliberately later — it is raw
//! ntdll FFI for numbers the snapshot already gives correctly).
//!
//! Termination is where Windows has no UNIX counterpart and honesty
//! matters most:
//!
//! - `TerminateProcess` is the whole story for force. There is no signal
//!   the target could catch, so `kill -KILL` really is the end.
//! - a graceful request exists only as `WM_CLOSE` posted to the target's
//!   top-level windows — what Task Manager's "End Task" does first. A
//!   process without windows (services, background tools) cannot be asked
//!   politely by a third party at all; console Ctrl events can only be
//!   delivered by the shell that spawned the process, which is winsh's
//!   core capability, not this applet's.

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
    TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, TerminateProcess, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
};

use super::{from_wide, last_error, WinErr};
use wmng_model::proc::ProcessRecord;

/// Win32 access right for a graceful/lazy open: read image, session, owner.
const QUERY: u32 = PROCESS_QUERY_LIMITED_INFORMATION;

pub fn list() -> Result<Vec<ProcessRecord>, String> {
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap as isize == -1 || snap.is_null() {
        return Err(format!("CreateToolhelp32Snapshot: {}", last_error().to_string()));
    }
    let mut out = Vec::new();
    let mut entry = PROCESSENTRY32W::default();
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    if unsafe { Process32FirstW(snap, &mut entry) } != 0 {
        loop {
            out.push(ProcessRecord {
                pid: entry.th32ProcessID,
                ppid: entry.th32ParentProcessID,
                threads: entry.cntThreads,
                name: from_wide(&entry.szExeFile),
                image: None,
                session: None,
                rss_kb: None,
                user: None,
            });
            if unsafe { Process32NextW(snap, &mut entry) } == 0 {
                break;
            }
        }
    }
    unsafe { CloseHandle(snap) };
    Ok(out)
}

/// Enriches one record with the details that need an open handle. Failures
/// are not errors — system processes refuse even administrators — the
/// fields simply stay empty and render as `-`.
pub fn enrich(rec: &mut ProcessRecord) {
    let Some(handle) = open(rec.pid, QUERY) else { return };

    let mut buf = [0u16; 1024];
    let mut len = buf.len() as u32;
    if unsafe { QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len) } != 0 {
        rec.image = Some(from_wide(&buf[..len as usize]));
    }

    let mut session = 0u32;
    if unsafe { ProcessIdToSessionId(rec.pid, &mut session) } != 0 {
        rec.session = Some(session);
    }

    let mut counters = PROCESS_MEMORY_COUNTERS::default();
    if unsafe {
        GetProcessMemoryInfo(
            handle,
            &mut counters,
            std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        )
    } != 0
    {
        rec.rss_kb = Some((counters.WorkingSetSize / 1024) as u64);
    }

    if let Some(user) = super::security::process_owner(handle) {
        rec.user = Some(user);
    }

    unsafe { CloseHandle(handle) };
}

fn open(pid: u32, access: u32) -> Option<HANDLE> {
    let h = unsafe { OpenProcess(access, 0, pid) };
    if h.is_null() || h as isize == -1 {
        None
    } else {
        Some(h)
    }
}

/// `kill -KILL pid` — TerminateProcess. There is nothing the target can do
/// about it, which is exactly what -KILL promises.
pub fn kill_force(pid: u32) -> Result<(), String> {
    let Some(handle) = open(pid, PROCESS_TERMINATE) else {
        let err = last_error();
        // OpenProcess reports a nonexistent pid as ERROR_INVALID_PARAMETER.
        if err.0 == 87 {
            return Err(format!("{pid}: no such process"));
        }
        return Err(format!("cannot open process {pid}: {}", err.to_string()));
    };
    let ok = unsafe { TerminateProcess(handle, 1) };
    let err = unsafe { GetLastError() };
    unsafe { CloseHandle(handle) };
    if ok == 0 {
        return Err(format!("terminate {pid}: {}", WinErr(err).to_string()));
    }
    Ok(())
}

/// `kill pid` (TERM, the default) — post `WM_CLOSE` to every top-level
/// window of the process. Returns how many windows were asked. Zero means
/// the process has no windows and cannot be asked politely from outside.
pub fn kill_graceful(pid: u32) -> Result<usize, String> {
    // Existence first: "no such process" and "no windows" are different
    // diagnoses, and confusing them sends the user hunting the wrong bug.
    if open(pid, QUERY).is_none() && last_error().0 == 87 {
        return Err(format!("{pid}: no such process"));
    }
    super::windows::close_windows_of(pid)
}
