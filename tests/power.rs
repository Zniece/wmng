//! Power applet tests — the SAFE paths only.
//!
//! A test suite must never be able to shut the machine down, so the real
//! `InitiateSystemShutdownExW` path is verified by hand and by code review;
//! here only argument handling, the tombstone-free command set, and the
//! nothing-to-abort error are exercised.

#![cfg(windows)]

use std::process::Command;

fn run(args: &[&str]) -> (String, String, i32) {
    let out = Command::new(env!("CARGO_BIN_EXE_wmng"))
        .args(args)
        .output()
        .expect("wmng binary exists");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

#[test]
fn shutdown_requires_a_time() {
    let (_, err, code) = run(&["shutdown"]);
    assert_eq!(code, 2);
    assert!(err.contains("missing time"), "{err}");
}

#[test]
fn invalid_time_specs_exit_two() {
    for spec in ["+x", "25:00", "12:61", "soon", "+"] {
        let (_, _, code) = run(&["shutdown", spec]);
        assert_eq!(code, 2, "{spec}");
    }
}

#[test]
fn reboot_and_poweroff_take_no_operands() {
    let (_, err, code) = run(&["reboot", "extra"]);
    assert_eq!(code, 2);
    assert!(err.starts_with("reboot:"), "{err}");
    let (_, err, code) = run(&["poweroff", "extra"]);
    assert_eq!(code, 2);
    assert!(err.starts_with("poweroff:"), "{err}");
}

#[test]
fn halt_does_not_exist() {
    // Windows cannot stand halted with power on. A command whose entire
    // referent is missing is DELETED, not aliased and not a refusal
    // stub: asking for it is like asking for any other unknown applet.
    let (_, err, code) = run(&["halt"]);
    assert_eq!(code, 2);
    assert!(err.contains("unknown applet"), "{err}");
}

#[test]
fn cancel_with_nothing_pending_is_a_clean_error() {
    // This is the one provider call that is unconditionally safe: it
    // aborts a shutdown that does not exist.
    let (_, err, code) = run(&["shutdown", "-c"]);
    if code == 0 {
        return; // a shutdown WAS pending (developer testing); cancelled.
    }
    assert_eq!(code, 1);
    assert!(err.contains("no shutdown is in progress"), "{err}");
}
