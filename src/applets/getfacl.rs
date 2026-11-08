//! getfacl — print access control lists, FreeBSD NFSv4 text form.
//!
//! Options mirror FreeBSD getfacl(1); `-R` is our addition (FreeBSD feeds
//! the same job to find | xargs). Windows-specific behaviour:
//!
//! - `-d` is a hard error: there are no default entries in NFSv4 ACLs,
//!   and Windows has no default-ACL concept to map it onto either.
//! - `-n` prints SIDs where FreeBSD prints numeric uid/gid.
//! - `-i` appends the SID (FreeBSD appends the uid/gid).
//! - An object with NO DACL at all (unrestricted access) is reported with
//!   a comment line instead of an empty list, because an empty ACL and a
//!   missing ACL mean opposite things.

use crate::providers;
use wmng_model::model::{self, FormatOpts};
use wmng_model::ops;

pub const USAGE: &str = "usage: getfacl [-dhinqRsv] [file ...]";

pub fn run(args: &[String]) -> i32 {
    let mut follow = true;
    let mut numeric = false;
    let mut verbose = false;
    let mut append_id = false;
    let mut opts = FormatOpts::default();
    let mut skip_base = false;
    let mut omit_header = false;
    let mut recurse = false;
    let mut files: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        let mut chars = a.chars();
        if chars.next() != Some('-') || a.len() == 1 {
            files.push(a.clone());
            i += 1;
            continue;
        }
        for c in chars {
            match c {
                'h' => follow = false,
                'i' => append_id = true,
                'n' => numeric = true,
                'q' => omit_header = true,
                's' => skip_base = true,
                'v' => verbose = true,
                'R' => recurse = true,
                'd' => {
                    eprintln!("getfacl: there are no default entries in NFSv4 ACLs");
                    return 2;
                }
                other => {
                    eprintln!("getfacl: -{other}: invalid option");
                    eprintln!("{USAGE}");
                    return 2;
                }
            }
        }
        i += 1;
    }

    // Names by default; -n keeps the SID text (FreeBSD prints the numeric
    // uid/gid there, and the SID is our number).
    if numeric {
        // -n: the SID text is the "number" — no name resolution at all.
        opts.numeric = true;
    } else {
        opts.verbose = verbose;
        opts.append_id = append_id;
        opts.sid_to_name = &|sid: &str| providers::lookup_sid(sid).0;
    }

    if files.is_empty() || files.iter().any(|f| f == "-") {
        // "-" (or no operands) means: read the file list from stdin, one
        // path per line. The list REPLACES the operands.
        use std::io::BufRead;
        let mut from_stdin = Vec::new();
        let stdin = std::io::stdin();
        for entry in stdin.lock().lines() {
            match entry {
                Ok(l) if !l.trim().is_empty() => from_stdin.push(l),
                Ok(_) => {}
                Err(e) => {
                    eprintln!("getfacl: stdin: {e}");
                    return 1;
                }
            }
        }
        files = from_stdin;
    }

    // Expand directories when -R was given; without it, fts-style preorder:
    // the directory itself, then its contents.
    let mut targets: Vec<(String, bool)> = Vec::new(); // (path, is_dir)
    let mut expand_error = false;
    for f in &files {
        match std::fs::metadata(f) {
            Ok(md) => {
                let is_dir = md.is_dir();
                if is_dir && !recurse {
                    // FreeBSD getfacl on a directory prints its ACL; do the
                    // same and simply never descend without -R.
                    targets.push((f.clone(), true));
                } else {
                    targets.push((f.clone(), is_dir));
                }
            }
            Err(e) => {
                eprintln!("getfacl: {f}: {e}");
                expand_error = true;
            }
        }
    }
    if expand_error {
        return 1;
    }
    if recurse {
        let mut expanded = Vec::new();
        for (p, is_dir) in &targets {
            expanded.push((p.clone(), *is_dir));
            if *is_dir {
                walk_dir_tree(p, &mut expanded);
            }
        }
        targets = expanded;
    }

    let mut printed_any = false;
    let mut ok = 0usize;
    let mut failed = 0usize;
    for (path, _) in &targets {
        match print_one(path, follow, skip_base, omit_header, &mut printed_any, &opts) {
            Ok(()) => ok += 1,
            Err(e) => {
                eprintln!("getfacl: {path}: {e}");
                failed += 1;
            }
        }
    }
    exit_code(ok, failed)
}

/// Preorder walk that never descends into reparse points (symlinks and
/// junctions): descending a junction can loop, and v1 has no way to walk
/// one safely. Skipped points are listed on stderr so silence never lies.
pub(crate) fn walk_dir_tree(dir: &str, out: &mut Vec<(String, bool)>) {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => {
            eprintln!("getfacl: {dir}: {e}");
            return;
        }
    };
    let mut entries: Vec<_> = rd.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let path = e.path();
        let p = path.display().to_string();
        match e.file_type() {
            Ok(ft) if ft.is_symlink() => {
                eprintln!("getfacl: {p}: reparse point, skipping");
            }
            Ok(ft) => {
                let is_dir = ft.is_dir();
                out.push((p.clone(), is_dir));
                if is_dir {
                    walk_dir_tree(&p, out);
                }
            }
            Err(er) => eprintln!("getfacl: {p}: {er}"),
        }
    }
}

fn print_one(
    path: &str,
    follow: bool,
    skip_base: bool,
    omit_header: bool,
    printed_any: &mut bool,
    opts: &FormatOpts,
) -> Result<(), String> {
    let sd = providers::read_sd(path, follow)?;

    let (explicit, inherited) = ops::split_inherited(&sd.aces);
    if skip_base && explicit.is_empty() {
        // -s: a file with no explicit entries has the "base" ACL that
        // inheritance alone produces — the Windows reading of "trivial".
        return Ok(());
    }

    if *printed_any {
        println!();
    }
    *printed_any = true;

    if sd.no_dacl {
        if !omit_header {
            println!("# file: {path}");
            println!("# no DACL: access is not restricted");
        }
        return Ok(());
    }

    if !omit_header {
        let owner_name = providers::lookup_sid(&sd.owner).0;
        let group_name = providers::lookup_sid(&sd.group).0;
        println!("# file: {path}");
        println!("# owner: {owner_name}");
        println!("# group: {group_name}");
    }

    for ace in explicit.iter().chain(inherited.iter()) {
        println!("{}", model::format_entry(ace, opts));
    }
    for raw in &sd.raw {
        let kind = if raw.inherited { "inherited" } else { "explicit" };
        println!("# {kind} unrepresentable ACE ({} bytes), preserved on rewrite", raw.bytes.len());
    }
    Ok(())
}

/// 0 = all fine; 1 = everything failed; 3 = some files failed (wmng exit
/// code convention; FreeBSD would return a plain 1).
pub(crate) fn exit_code(ok: usize, failed: usize) -> i32 {
    match (ok, failed) {
        (_, 0) => 0,
        (0, _) => 1,
        _ => 3,
    }
}
