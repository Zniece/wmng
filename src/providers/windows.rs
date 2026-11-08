//! User32 bindings: the graceful side of `kill`.
//!
//! `WM_CLOSE` to a window is the closest thing Windows has to a polite
//! "please exit" that a third party can deliver: it is exactly what Task
//! Manager's "End Task" sends first. The process is free to decline (a
//! save-changes prompt), which is what a catchable TERM amounts to here.

use windows_sys::Win32::Foundation::{HWND, LPARAM};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetWindowThreadProcessId, PostMessageW, WM_CLOSE,
};

/// Posts WM_CLOSE to every top-level window owned by `pid`. Returns how
/// many windows were asked; zero means the process has nothing to close
/// and cannot be asked politely from outside.
///
/// # Safety of the callback
///
/// EnumWindows invokes our callback with window handles on the calling
/// thread; the pid travels in LPARAM. The callback only calls Win32
/// query/post functions with those handles.
pub fn close_windows_of(pid: u32) -> Result<usize, String> {
    struct Ctx {
        pid: u32,
        sent: usize,
    }
    let mut ctx = Ctx { pid, sent: 0 };
    extern "system" fn on_window(hwnd: HWND, lparam: LPARAM) -> i32 {
        let ctx = unsafe { &mut *(lparam as *mut Ctx) };
        let mut owner = 0u32;
        unsafe { GetWindowThreadProcessId(hwnd, &mut owner) };
        if owner == ctx.pid {
            let ok = unsafe { PostMessageW(hwnd, WM_CLOSE, 0, 0) };
            if ok != 0 {
                ctx.sent += 1;
            }
        }
        1 // keep enumerating
    }
    let ok = unsafe {
        EnumWindows(Some(on_window), &mut ctx as *mut Ctx as LPARAM)
    };
    if ok == 0 {
        // Callback failure only; windows already posted stay posted.
        return Err("EnumWindows failed".into());
    }
    Ok(ctx.sent)
}
