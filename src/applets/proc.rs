//! ps / pgrep / pkill / kill — process inspection and control.
//!
//! FreeBSD command shapes; Win32 mechanisms. The semantic decisions:
//!
//! - `ps` lists every process by default (FreeBSD lists only your own;
//!   the "own only" filter needs a token query per process and buys
//!   little on a single-user desktop). `-f` widens the columns, `-o`
//!   selects them.
//! - `kill PID` (TERM, the default) posts `WM_CLOSE` to the target's
//!   windows — the only polite exit request a third party can deliver on
//!   Windows. A process with no windows cannot be asked politely; that
//!   is reported, not faked. Console Ctrl events belong to the shell
//!   that owns the child (winsh), not to a standalone applet.
//! - `kill -KILL PID` is TerminateProcess: sudden, uncapturable, honest.
//! - `kill -INT` / `-BREAK` are refused: they name console events that
//!   can only be delivered by the spawning shell.

use crate::providers;
use wmng_model::proc as model;

pub const PS_USAGE: &str = "usage: ps [-f] [-o fields]";
pub const PGREP_USAGE: &str = "usage: pgrep [-f] [-u user] pattern";
pub const PKILL_USAGE: &str = "usage: pkill [-f] [-u user] [-KILL] pattern";
pub const KILL_USAGE: &str = "usage: kill [-l] [-TERM | -KILL] pid ...";

#[derive(Clone, Copy, PartialEq)]
pub enum Signal {
    Term,
    Kill,
}

pub fn run_ps(args: &[String]) -> i32 {
    let mut full = false;
    let mut fields = None;
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        let mut chars = a.chars();
        if chars.next() != Some('-') || a.len() == 1 {
            eprintln!("ps: unexpected operand {a:?}");
            return 2;
        }
        match chars.next() {
            Some('f') => full = true,
            None => {}
            Some('o') => {
                i += 1;
                match args.get(i) {
                    Some(spec) => match model::validate_fields(spec) {
                        Ok(f) => fields = Some(f),
                        Err(e) => {
                            eprintln!("ps: {e}");
                            return 2;
                        }
                    },
                    None => {
                        eprintln!("ps: -o: missing field list");
                        return 2;
                    }
                }
            }
            Some(other) => {
                eprintln!("ps: -{other}: invalid option");
                return 2;
            }
        }
        i += 1;
    }

    let fields = fields.unwrap_or_else(|| {
        if full {
            vec![
                "pid".into(),
                "ppid".into(),
                "session".into(),
                "threads".into(),
                "rss".into(),
                "user".into(),
                "image".into(),
            ]
        } else {
            vec!["pid".into(), "ppid".into(), "name".into()]
        }
    });

    let mut records = match providers::process::list() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("ps: {e}");
            return 1;
        }
    };
    records.sort_by_key(|r| r.pid);
    if full {
        for r in &mut records {
            providers::process::enrich(r);
        }
    }
    print!("{}", model::format_table(&records, &fields));
    0
}

/// Common collection for pgrep/pkill: list, filter by pattern and user.
fn find(args: &[String], usage: &str) -> Option<(Vec<model::ProcessRecord>, bool, Signal)> {
    let mut full = false;
    let mut user: Option<String> = None;
    let mut signal = Signal::Term;
    let mut pattern: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "-f" {
            full = true;
        } else if a == "-KILL" {
            signal = Signal::Kill;
        } else if a == "-u" {
            i += 1;
            match args.get(i) {
                Some(u) => user = Some(u.clone()),
                None => {
                    eprintln!("{usage}: -u: missing user");
                    return None;
                }
            }
        } else if let Some(rest) = a.strip_prefix('-') {
            eprintln!("{usage}: -{rest}: invalid option");
            return None;
        } else if pattern.is_none() {
            pattern = Some(a.clone());
        } else {
            eprintln!("{usage}: only one pattern");
            return None;
        }
        i += 1;
    }
    let Some(pattern) = pattern else {
        eprintln!("{usage}: missing pattern");
        return None;
    };

    let mut records = providers::process::list().ok()?;
    for r in &mut records {
        // -f needs image paths; -u needs owners. Enrichment is the price.
        providers::process::enrich(r);
    }
    let mut hits = records
        .into_iter()
        .filter(|r| model::matches(r, &pattern, full))
        .collect::<Vec<_>>();
    if let Some(u) = &user {
        hits.retain(|r| r.user.as_deref() == Some(u.as_str()));
    }
    Some((hits, full, signal))
}

pub fn run_pgrep(args: &[String]) -> i32 {
    let Some((hits, _, _)) = find(args, PGREP_USAGE) else {
        return 2;
    };
    for r in &hits {
        println!("{}", r.pid);
    }
    if hits.is_empty() {
        1
    } else {
        0
    }
}

pub fn run_pkill(args: &[String]) -> i32 {
    let Some((hits, _, signal)) = find(args, PKILL_USAGE) else {
        return 2;
    };
    let mut failed = 0usize;
    for r in &hits {
        if let Err(e) = deliver(r.pid, signal) {
            eprintln!("pkill: {}: {e}", r.pid);
            failed += 1;
        }
    }
    match (hits.len(), failed) {
        (0, _) => 1,
        (_, 0) => 0,
        (n, f) if n == f => 1,
        _ => 3,
    }
}

pub fn run_kill(args: &[String]) -> i32 {
    let mut signal = Signal::Term;
    let mut pids: Vec<u32> = Vec::new();
    for a in args {
        if a == "-l" {
            println!("TERM KILL");
            return 0;
        }
        if let Some(rest) = a.strip_prefix('-') {
            signal = match rest {
                "TERM" => Signal::Term,
                "KILL" => Signal::Kill,
                "INT" | "BREAK" => {
                    eprintln!(
                        "kill: -{rest}: console events can only be delivered by the shell \
                         that spawned the process (winsh), not by a standalone kill"
                    );
                    return 2;
                }
                other => {
                    eprintln!("kill: -{other}: unknown signal");
                    return 2;
                }
            };
            continue;
        }
        match a.parse::<u32>() {
            Ok(p) => pids.push(p),
            Err(_) => {
                eprintln!("kill: {a}: not a pid");
                return 2;
            }
        }
    }
    if pids.is_empty() {
        eprintln!("{KILL_USAGE}");
        return 2;
    }
    let total = pids.len();
    let mut failed = 0usize;
    for pid in pids {
        if let Err(e) = deliver(pid, signal) {
            eprintln!("kill: {e}");
            failed += 1;
        }
    }
    match (total, failed) {
        (_, 0) => 0,
        (n, f) if n == f => 1,
        _ => 3,
    }
}

fn deliver(pid: u32, signal: Signal) -> Result<(), String> {
    match signal {
        Signal::Kill => providers::process::kill_force(pid),
        Signal::Term => {
            let sent = providers::process::kill_graceful(pid)?;
            if sent == 0 {
                return Err(format!(
                    "{pid}: no windows to close; TERM cannot be delivered to a windowless \
                     process from outside (use kill -KILL)"
                ));
            }
            Ok(())
        }
    }
}
