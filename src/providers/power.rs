//! System power: shutdown, reboot, cancel.
//!
//! One API pair covers everything `shutdown(8)` needs:
//!
//! - `InitiateSystemShutdownExW` — timeout in seconds, broadcast message,
//!   force-close-apps flag, reboot flag, reason code. This is the direct
//!   counterpart of FreeBSD's "warn users, wait, then bring it down".
//! - `AbortSystemShutdownW` — FreeBSD's `shutdown -c`.
//!
//! Both need `SeShutdownPrivilege`, which admin tokens hold but DISABLED
//! by default; `AdjustTokenPrivileges` turns it on. A standard-user token
//! does not hold it at all, and the error must say so ("run elevated"),
//! not just "access denied".
//!
//! The reason code is a native concept with no UNIX counterpart; we always
//! report a planned shutdown rather than letting Windows log a misleading
//! "unexpected" reason.

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, LUID};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES,
    SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows_sys::Win32::System::Shutdown::{
    AbortSystemShutdownW, InitiateSystemShutdownExW, SHTDN_REASON_FLAG_PLANNED,
    SHTDN_REASON_MAJOR_OTHER, SHTDN_REASON_MINOR_OTHER,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use super::{to_wide, WinErr};

const SE_SHUTDOWN_NAME: &str = "SeShutdownPrivilege";

/// Enables the shutdown privilege in our own token.
///
/// `AdjustTokenPrivileges` reports success even when the privilege is
/// merely absent, so the check is the error code afterwards.
fn enable_shutdown_privilege() -> Result<(), String> {
    let mut luid = LUID { LowPart: 0, HighPart: 0 };
    let name = to_wide(SE_SHUTDOWN_NAME);
    if unsafe { LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &mut luid) } == 0 {
        return Err(format!(
            "LookupPrivilegeValue({SE_SHUTDOWN_NAME}): {}",
            WinErr(unsafe { GetLastError() }).to_string()
        ));
    }

    let mut token: HANDLE = std::ptr::null_mut();
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
    } == 0 {
        return Err(format!(
            "OpenProcessToken: {}",
            WinErr(unsafe { GetLastError() }).to_string()
        ));
    }

    let state = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    unsafe { AdjustTokenPrivileges(token, 0, &state, 0, std::ptr::null_mut(), std::ptr::null_mut()) };
    let err = unsafe { GetLastError() };
    unsafe { CloseHandle(token) };

    // 1314 = ERROR_PRIVILEGE_NOT_HELD: the token does not have the
    // shutdown privilege at all. Say what the user must do about it.
    if err == 1314 {
        return Err("shutdown requires the SeShutdownPrivilege; run elevated".into());
    }
    if err != 0 {
        return Err(format!("AdjustTokenPrivileges: {}", WinErr(err).to_string()));
    }
    Ok(())
}

/// Requests a system shutdown or reboot.
///
/// `timeout_secs` is how long logged-on users get before the system goes
/// down; `message` is shown to them; `force` closes applications without
/// saving (documented as the Windows force, not FreeBSD's fsck flags).
pub fn request(reboot: bool, force: bool, timeout_secs: u32, message: &str) -> Result<(), String> {
    enable_shutdown_privilege()?;
    let msg = to_wide(message);
    let ok = unsafe {
        InitiateSystemShutdownExW(
            std::ptr::null(), // local machine
            msg.as_ptr(),
            timeout_secs,
            force as i32,
            reboot as i32,
            SHTDN_REASON_FLAG_PLANNED | SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_MINOR_OTHER,
        )
    };
    if ok == 0 {
        let err = unsafe { GetLastError() };
        // 1115/1116: a shutdown is already scheduled or in progress.
        if err == 1115 || err == 1116 {
            return Err("a shutdown is already scheduled".into());
        }
        return Err(WinErr(err).to_string());
    }
    Ok(())
}

/// Cancels a pending shutdown (`shutdown -c`).
pub fn cancel() -> Result<(), String> {
    enable_shutdown_privilege()?;
    if unsafe { AbortSystemShutdownW(std::ptr::null()) } == 0 {
        let err = unsafe { GetLastError() };
        // Nothing to abort reports the same code family.
        if err == 1115 || err == 1116 || err == 1190 {
            return Err("no shutdown is in progress".into());
        }
        return Err(WinErr(err).to_string());
    }
    Ok(())
}
