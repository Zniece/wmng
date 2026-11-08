//! setfacl — modify access control lists.
//!
//! The option queue is FreeBSD's central design point and is kept
//! verbatim: every option becomes one operation, applied strictly in
//! command-line order, so `-m a -x b -m c` and `-m a -m c -x b` can
//! legitimately differ.
//!
//! Windows deviations (ACL-PORT-SPEC §4), all forced by the platform:
//!
//! - inherited ACEs are read-only: `-x` against one is a clear refusal,
//!   never a silent no-op (which is what `icacls /remove` does);
//! - the explicit section is re-sorted deny-before-allow after edits,
//!   because Windows evaluates a DACL strictly in order;
//! - `-b` removes explicit entries and keeps inherited ones; it refuses
//!   to build an empty DACL, which would mean "deny everyone";
//! - `-d`/`-k` are hard errors, `-n` is accepted and ignored.

use crate::providers;
use wmng_model::model::{self, Ace, ResolveNames};
use wmng_model::ops;

pub const USAGE: &str = "usage: setfacl [-R [-H | -L | -P]] [-bdhkn] [-a position entries] \
[-m entries] [-M file] [-x entries] [-X file] [file ...]";

/// One queued operation, in command-line order.
enum Op {
    Merge(Vec<Ace>),
    Remove(Vec<Ace>),
    RemoveByNumber(usize),
    RemoveAllExplicit,
    Insert(usize, Vec<Ace>),
}

/// Name → SID via the system lookup. A `S-1-…` string is taken literally,
/// so both `user:*S-1-5-18` (icacls spelling) and `user:S-1-5-18` work.
struct SysResolver;

impl ResolveNames for SysResolver {
    fn resolve(&mut self, qualifier: &str) -> Option<model::Sid> {
        if model::is_sid(qualifier) {
            return Some(qualifier.to_string());
        }
        providers::lookup_name(qualifier).map(|(sid, _)| sid)
    }
}

fn parse_entries(text: &str) -> Result<Vec<Ace>, String> {
    let mut r = SysResolver;
    model::parse_acl_text(text, &mut r)
}

fn read_acl_file(path: &str) -> Result<Vec<Ace>, String> {
    let text = if path == "-" {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| e.to_string())?;
        buf
    } else {
        std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?
    };
    parse_entries(&text)
}

pub fn run(args: &[String]) -> i32 {
    let mut queue: Vec<Op> = Vec::new();
    let mut recurse = false;
    let mut follow = true;
    let mut saw_ops = false;
    let mut saw_n = false;

    let mut files: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i < args.len() {
        let a = &args[i];
        let mut chars = a.chars();
        if chars.next() != Some('-') || a.len() == 1 {
            files.push(a.clone());
            i += 1;
            continue;
        }
        // Options that take a value consume the next argv element.
        while let Some(c) = chars.next() {
            let outcome: Result<(), String> = match c {
                'R' => {
                    recurse = true;
                    Ok(())
                }
                'H' | 'L' | 'P' => {
                    // Symlink traversal policy. v1 never descends into
                    // reparse points (junctions can loop); the flags are
                    // accepted so FreeBSD-style scripts still run.
                    Ok(())
                }
                'h' => {
                    follow = false;
                    Ok(())
                }
                'n' => {
                    // POSIX mask recalculation does not exist here; the
                    // flag is accepted and ignored on purpose (spec §4.4).
                    saw_n = true;
                    Ok(())
                }
                'm' | 'M' | 'x' | 'X' => {
                    i += 1;
                    let Some(v) = args.get(i).cloned() else {
                        return usage_err(&format!("-{c}: missing argument"));
                    };
                    let op = match c {
                        'm' => parse_entries(&v).map(Op::Merge),
                        'M' => read_acl_file(&v).map(Op::Merge),
                        'X' => read_acl_file(&v).map(Op::Remove),
                        // -x: an all-numeric argument removes by position,
                        // anything else by entry.
                        _ => {
                            if v.chars().all(|ch| ch.is_ascii_digit()) && !v.is_empty() {
                                Ok(Op::RemoveByNumber(v.parse().unwrap()))
                            } else {
                                parse_entries(&v).map(Op::Remove)
                            }
                        }
                    };
                    match op {
                        Ok(op) => {
                            queue.push(op);
                            Ok(())
                        }
                        Err(e) => Err(e),
                    }
                }
                'a' => {
                    i += 1;
                    let pos = match args.get(i) {
                        Some(p) => p.clone(),
                        None => return usage_err(&format!("-a: missing position")),
                    };
                    i += 1;
                    let entries = match args.get(i) {
                        Some(e) => e.clone(),
                        None => return usage_err(&format!("-a {pos}: missing ACL")),
                    };
                    match pos.parse::<usize>() {
                        Ok(n) => match parse_entries(&entries) {
                            Ok(e) => {
                                queue.push(Op::Insert(n, e));
                                Ok(())
                            }
                            Err(e) => Err(e),
                        },
                        Err(_) => Err(format!("{pos}: invalid entry number")),
                    }
                }
                'b' => {
                    queue.push(Op::RemoveAllExplicit);
                    Ok(())
                }
                'k' => Err("there are no default entries in NFSv4 ACLs; cannot remove".into()),
                'd' => Err("there are no default entries in NFSv4 ACLs".into()),
                other => Err(format!("-{other}: invalid option")),
            };
            match outcome {
                Ok(()) => {
                    if !matches!(c, 'R' | 'H' | 'L' | 'P' | 'h' | 'n') {
                        saw_ops = true;
                    }
                }
                Err(e) => return usage_err(&e),
            }
        }
        i += 1;
    }

    if !saw_ops && !saw_n {
        eprintln!("{USAGE}");
        return 2;
    }
    if recurse && !follow {
        eprintln!("setfacl: the -R and -h options may not be specified together.");
        return 2;
    }

    // No operands (or only "-"): read the file list from stdin.
    if files.is_empty() || files.iter().any(|f| f == "-") {
        use std::io::BufRead;
        let stdin = std::io::stdin();
        let mut from_stdin = Vec::new();
        for entry in stdin.lock().lines() {
            match entry {
                Ok(l) if !l.trim().is_empty() => from_stdin.push(l),
                Ok(_) => {}
                Err(e) => {
                    eprintln!("setfacl: stdin: {e}");
                    return 1;
                }
            }
        }
        files = from_stdin;
    }

    // Preorder expansion for -R, identical policy to getfacl.
    let mut targets: Vec<(String, bool)> = Vec::new();
    let mut root_failures = 0usize;
    for f in &files {
        match std::fs::metadata(f) {
            Ok(md) => targets.push((f.clone(), md.is_dir())),
            Err(e) => {
                eprintln!("setfacl: {f}: {e}");
                root_failures += 1;
            }
        }
    }
    if recurse {
        let mut expanded = Vec::new();
        for (p, is_dir) in &targets {
            expanded.push((p.clone(), *is_dir));
            if *is_dir {
                crate::applets::getfacl::walk_dir_tree(p, &mut expanded);
            }
        }
        targets = expanded;
    }

    let mut ok = 0usize;
    let mut failed = root_failures;
    for (path, is_dir) in &targets {
        match handle_file(path, *is_dir, &queue, follow) {
            Ok(()) => ok += 1,
            Err(e) => {
                eprintln!("setfacl: {path}: {e}");
                failed += 1;
            }
        }
    }
    crate::applets::getfacl::exit_code(ok, failed)
}

fn usage_err(msg: &str) -> i32 {
    eprintln!("setfacl: {msg}");
    eprintln!("{USAGE}");
    2
}

fn handle_file(path: &str, is_dir: bool, queue: &[Op], follow: bool) -> Result<(), String> {
    let sd = providers::read_sd(path, follow)?;
    let (mut explicit, inherited) = ops::split_inherited(&sd.aces);
    let (mut raw_explicit, raw_inherited): (Vec<_>, Vec<_>) =
        sd.raw.iter().cloned().partition(|r| !r.inherited);

    for op in queue {
        match op {
            Op::Merge(entries) => {
                // On a file, inheritance flags from the pending entries are
                // cleared first: a file cannot inherit (FreeBSD
                // clear_inheritance_flags).
                let entries = if !is_dir {
                    ops::clear_inheritance_flags(entries)
                } else {
                    entries.clone()
                };
                ops::merge(&entries, &mut explicit, &inherited)?;
            }
            Op::Remove(spec) => {
                let missed = ops::remove(spec, &mut explicit);
                for want in &missed {
                    if inherited.iter().any(|e| e.same_key(want)) {
                        return Err(
                            "entry is inherited from the parent directory; modify the parent, \
                             or break inheritance first"
                                .into(),
                        );
                    }
                }
                if !missed.is_empty() {
                    return Err("cannot remove non-existent ACL entry".into());
                }
            }
            Op::RemoveByNumber(n) => {
                // Numbers count the displayed list: explicit first, then
                // inherited.
                if *n < explicit.len() {
                    if !ops::remove_by_number(*n, &mut explicit) {
                        return Err(format!("no ACL entry numbered {n}"));
                    }
                } else if *n < explicit.len() + inherited.len() {
                    return Err(
                        "entry is inherited from the parent directory; modify the parent, \
                         or break inheritance first"
                            .into(),
                    );
                } else {
                    return Err(format!("no ACL entry numbered {n}"));
                }
            }
            Op::RemoveAllExplicit => {
                // -b undoes every explicit change, including exotic
                // explicit entries we can only carry verbatim. An empty
                // FINAL DACL is refused at the write step.
                ops::remove_all_explicit(&mut explicit);
                raw_explicit.clear();
            }
            Op::Insert(position, entries) => {
                let entries = if !is_dir {
                    ops::clear_inheritance_flags(entries)
                } else {
                    entries.clone()
                };
                ops::insert_at(*position, &entries, &mut explicit)?;
            }
        }
    }

    if explicit.is_empty()
        && raw_explicit.is_empty()
        && inherited.is_empty()
        && raw_inherited.is_empty()
    {
        return Err("refusing to write an empty DACL, which denies everyone".into());
    }

    // group@ becomes the object's primary group SID before serialising.
    let mut explicit = explicit;
    let mut inherited = inherited;
    providers::reify_group(&mut explicit, &sd.group);
    providers::reify_group(&mut inherited, &sd.group);

    let acl = providers::build_acl(&explicit, &raw_explicit, &inherited, &raw_inherited);
    providers::write_dacl(path, follow, &acl)
}
