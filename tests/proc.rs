//! Process applet tests — read-only and failure paths only.
//!
//! Killing a live process in a test would make the suite order-dependent
//! and occasionally wrong (pid reuse); the force path was verified by
//! hand against a spawned ping. What a test CAN do safely is enumerated
//! here.

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
fn ps_lists_the_system_process() {
    let (out, _, code) = run(&["ps"]);
    assert_eq!(code, 0);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[0], "    PID    PPID NAME");
    // PID 4 "System" exists on every Windows machine ever.
    assert!(
        out.lines().any(|l| l.ends_with("System")),
        "pid 4 must appear"
    );
}

#[test]
fn ps_o_selects_columns() {
    let (out, _, code) = run(&["ps", "-o", "pid,name"]);
    assert_eq!(code, 0);
    assert!(out.starts_with("    PID NAME"), "{out}");
    let (_, err, code) = run(&["ps", "-o", "pid,bogus"]);
    assert_eq!(code, 2);
    assert!(err.contains("unknown field"), "{err}");
}

#[test]
fn ps_f_has_the_full_columns() {
    let (out, _, code) = run(&["ps", "-f"]);
    assert_eq!(code, 0);
    assert!(out.contains("SESS") && out.contains("RSS") && out.contains("IMAGE"));
}

#[test]
fn pgrep_is_case_insensitive() {
    // The OS spells process names inconsistently (PING.EXE, svchost.exe);
    // a case-sensitive match would be a coin flip.
    let (out, _, code) = run(&["pgrep", "SYSTEM"]);
    assert_eq!(code, 0);
    assert!(out.lines().any(|l| l.trim() == "4"), "pid 4 for System");
}

#[test]
fn pgrep_no_match_exits_one() {
    let (out, _, code) = run(&["pgrep", "definitely-not-running-xyzzy"]);
    assert_eq!(code, 1);
    assert!(out.trim().is_empty());
}

#[test]
fn kill_reports_no_such_process() {
    // A pid that cannot exist: beyond anything a box has ever had.
    let (_, err, code) = run(&["kill", "999999999"]);
    assert_eq!(code, 1);
    assert!(err.contains("no such process"), "{err}");
}

#[test]
fn kill_int_is_refused_with_an_explanation() {
    let (_, err, code) = run(&["kill", "-INT", "4"]);
    assert_eq!(code, 2);
    // The message must say WHY and WHERE the capability lives.
    assert!(err.contains("winsh"), "{err}");
}

#[test]
fn kill_l_lists_the_two_signals() {
    let (out, _, code) = run(&["kill", "-l"]);
    assert_eq!(code, 0);
    assert!(out.contains("TERM") && out.contains("KILL"));
}
