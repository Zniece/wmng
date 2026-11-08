//! shutdown / reboot / poweroff — FreeBSD shutdown(8) style.
//!
//! FreeBSD syntax on a Windows mechanism: `InitiateSystemShutdownExW` gives
//! the timeout (logged-on users see a dialog counting down), the broadcast
//! message, the force-apps-close flag and the reboot flag — the same knobs
//! FreeBSD's shutdown(8) exposes.
//!
//! Deviations, all forced by the platform:
//!
//! - default action is POWER OFF. FreeBSD's default is halt, but Windows
//!   has no halt-with-power-on state; a plain `shutdown` doing what
//!   `poweroff` does is the least surprising reading on this platform.
//!   `halt` itself does not exist as a command at all: it names a state
//!   Windows cannot represent, and the rule is to delete such commands,
//!   not to alias them or plant a refusal in their place.
//! - single-user mode does not exist; `shutdown now` just runs at once.
//! - `-f` is the WINDOWS force (close applications without saving), not
//!   FreeBSD's fsck flags, which mean nothing here.
//!
//! Every real request needs `SeShutdownPrivilege`; the error message says
//! "run elevated" rather than a bare "access denied".

use crate::providers;
use wmng_model::time;

pub const SHUTDOWN_USAGE: &str =
    "usage: shutdown [-p | -r] [-f] [-c] [now | +minutes | hh:mm] [message ...]";

#[derive(Clone, Copy, PartialEq)]
enum Action {
    PowerOff,
    Reboot,
}

pub fn run_shutdown(args: &[String]) -> i32 {
    let mut action = Action::PowerOff;
    let mut force = false;
    let mut cancel = false;
    let mut operands: Vec<String> = Vec::new();

    for a in args {
        if let Some(opts) = a.strip_prefix('-') {
            if opts.is_empty() {
                operands.push(a.clone());
                continue;
            }
            for c in opts.chars() {
                match c {
                    'p' => action = Action::PowerOff,
                    'r' => action = Action::Reboot,
                    'f' => force = true,
                    'c' => cancel = true,
                    other => return usage_err(&format!("-{other}: invalid option"), "shutdown"),
                }
            }
        } else {
            operands.push(a.clone());
        }
    }

    if cancel {
        if !operands.is_empty() {
            return usage_err("-c takes no time or message", "shutdown");
        }
        return match providers::power::cancel() {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("shutdown: {e}");
                1
            }
        };
    }

    let Some(time_spec) = operands.first() else {
        return usage_err("missing time", "shutdown");
    };
    let message = operands[1..].join(" ");

    let secs_of_day = seconds_of_day();
    let secs = match time::parse(time_spec, secs_of_day) {
        Ok(s) => s,
        Err(e) => return usage_err(&e, "shutdown"),
    };

    match providers::power::request(action == Action::Reboot, force, secs, &message) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("shutdown: {e}");
            1
        }
    }
}

/// `reboot [-f]` — shutdown -r now.
pub fn run_reboot(args: &[String]) -> i32 {
    let force = match args {
        [a] if a == "-f" => true,
        [] => false,
        _ => return usage_err("reboot takes no other arguments", "reboot"),
    };
    finish(Action::Reboot, force, 0, String::new())
}

/// `poweroff [-f]` — shutdown -p now.
pub fn run_poweroff(args: &[String]) -> i32 {
    let force = match args {
        [a] if a == "-f" => true,
        [] => false,
        _ => return usage_err("poweroff takes no other arguments", "poweroff"),
    };
    finish(Action::PowerOff, force, 0, String::new())
}

fn finish(action: Action, force: bool, secs: u32, message: String) -> i32 {
    match providers::power::request(action == Action::Reboot, force, secs, &message) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("{}: {e}", prog_of(action));
            1
        }
    }
}

fn prog_of(a: Action) -> &'static str {
    match a {
        Action::PowerOff => "poweroff",
        Action::Reboot => "reboot",
    }
}

/// Local time of day in seconds, so an absolute `hh:mm` spec means what
/// the wall clock says. Computing it from the epoch would land in UTC and
/// be off by the zone — a bug with a comment is still a bug.
fn seconds_of_day() -> u32 {
    use windows_sys::Win32::Foundation::SYSTEMTIME;
    use windows_sys::Win32::System::SystemInformation::GetLocalTime;
    let mut st = SYSTEMTIME {
        wYear: 0, wMonth: 0, wDayOfWeek: 0, wDay: 0,
        wHour: 0, wMinute: 0, wSecond: 0, wMilliseconds: 0,
    };
    unsafe { GetLocalTime(&mut st) };
    (st.wHour as u32) * 3600 + (st.wMinute as u32) * 60 + st.wSecond as u32
}

fn usage_err(msg: &str, prog: &str) -> i32 {
    eprintln!("{prog}: {msg}");
    if prog == "shutdown" {
        eprintln!("{SHUTDOWN_USAGE}");
    } else {
        eprintln!("usage: {prog} [-f]");
    }
    2
}
