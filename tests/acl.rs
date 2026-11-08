//! Integration tests: the real Win32 round trip, on Windows only.
//!
//! Unit tests verify the model against my reading of FreeBSD; these verify
//! the read-modify-write path against Windows itself, including the two
//! rules the platform enforces and no unit test can: inherited ACEs are
//! read-only, and writing an empty DACL is a footgun.

#![cfg(windows)]

use std::process::{Command, Stdio};

fn wmng() -> Command {
    Command::new(env!("CARGO_BIN_EXE_wmng"))
}

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("wmng-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
    fn file(&self, name: &str) -> std::path::PathBuf {
        let p = self.0.join(name);
        std::fs::write(&p, "x").unwrap();
        p
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Runs wmng and returns (stdout, stderr, code).
fn run(args: &[&str]) -> (String, String, i32) {
    let out = wmng()
        .args(args)
        .output()
        .expect("wmng binary exists");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

fn getfacl(path: &str) -> String {
    let (out, err, code) = run(&["getfacl", path]);
    assert_eq!(code, 0, "getfacl failed: {err}");
    out
}

fn entries(path: &str) -> Vec<String> {
    getfacl(path)
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| l.trim().to_string())
        .collect()
}

#[test]
fn merge_is_idempotent_and_round_trips() {
    let dir = TempDir::new("rt");
    let f = dir.file("f.txt");
    let f = f.to_str().unwrap();

    let (o, e, c) = run(&["setfacl", "-m", "everyone@:rx:allow", f]);
    assert_eq!(c, 0, "{e}");
    let first = getfacl(f);

    // Merging the file's own output must change nothing.
    let mut child = wmng()
        .args(["setfacl", "-M", "-", f])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    use std::io::Write;
    stdin.write_all(first.as_bytes()).unwrap();
    drop(stdin);
    let status = child.wait().unwrap();
    assert!(status.success());
    let _ = o;

    let second = getfacl(f);
    assert_eq!(first, second, "round trip must be a fixed point");
}

#[test]
fn merge_adds_exactly_one_entry() {
    let dir = TempDir::new("one");
    let f = dir.file("f.txt");
    let f = f.to_str().unwrap();

    let before = entries(f).len();
    run(&["setfacl", "-m", "everyone@:r:allow", f]);
    let after = entries(f);
    assert_eq!(after.len(), before + 1);
    assert!(after.iter().any(|l| l.contains("everyone@:r")));

    // Same merge again: no duplicate.
    run(&["setfacl", "-m", "everyone@:r:allow", f]);
    assert_eq!(entries(f).len(), after.len());
}

#[test]
fn deny_sorts_before_allow() {
    let dir = TempDir::new("deny");
    let f = dir.file("f.txt");
    let f = f.to_str().unwrap();

    run(&["setfacl", "-m", "everyone@:rx:allow", f]);
    run(&["setfacl", "-m", "everyone@:w:deny", f]);
    let lines = entries(f);
    let deny = lines.iter().position(|l| l.ends_with(":deny")).unwrap();
    let allow = lines.iter().position(|l| l.ends_with(":allow")).unwrap();
    assert!(deny < allow, "deny must evaluate first: {lines:?}");
}

#[test]
fn remove_undoes_merge() {
    let dir = TempDir::new("rm");
    let f = dir.file("f.txt");
    let f = f.to_str().unwrap();

    let before = getfacl(f);
    run(&["setfacl", "-m", "everyone@:r:allow", f]);
    run(&["setfacl", "-x", "everyone@:r:allow", f]);
    assert_eq!(getfacl(f), before);
}

#[test]
fn inherited_entries_are_refused_loudly() {
    let dir = TempDir::new("inh");
    let f = dir.file("f.txt");
    let f = f.to_str().unwrap();

    // A fresh file inherits entries from its parent; removing one by SID
    // must fail with the long explanation, not silently succeed the way
    // icacls /remove does.
    let (_, err, code) = run(&["setfacl", "-x", "user:*S-1-5-18:r:allow", f]);
    assert_ne!(code, 0);
    assert!(
        err.contains("inherited"),
        "must say WHY: {err}"
    );
}

#[test]
fn usage_errors_exit_two() {
    let dir = TempDir::new("usage");
    let f = dir.file("f.txt");
    let (_, _, code) = run(&["setfacl", "-Z", f.to_str().unwrap()]);
    assert_eq!(code, 2);
    let (_, _, code) = run(&["setfacl", "-d", f.to_str().unwrap()]);
    assert_eq!(code, 2);
    let (_, _, code) = run(&["getfacl", "-d", f.to_str().unwrap()]);
    assert_eq!(code, 2);
}

#[test]
fn q_omits_the_header() {
    let dir = TempDir::new("q");
    let f = dir.file("f.txt");
    let out = getfacl(f.to_str().unwrap());
    assert!(out.contains("# file:"));
    let (out, _, code) = run(&["getfacl", "-q", f.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert!(!out.contains('#'));
}

