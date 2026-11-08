//! Process domain model: records, ps column layout, pgrep matching.
//!
//! Pure Rust, no Win32 — the provider fills records, this decides how they
//! are rendered and matched. Column set is a deliberate mix: the SHAPE is
//! FreeBSD ps (fixed-width columns, header line), the COLUMNS are what
//! Windows actually has (session id instead of a controlling tty; no cpu
//! time until GetProcessTimes is wired in).

/// One process, as far as the model cares. `Option` fields are filled in
/// by the provider only for processes it could open; access to a system
/// process is denied even for administrators, and the table must not lie
/// about them.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProcessRecord {
    pub pid: u32,
    pub ppid: u32,
    pub threads: u32,
    /// Exe file name, e.g. `explorer.exe` (from the snapshot).
    pub name: String,
    /// Full image path, when the process could be opened.
    pub image: Option<String>,
    /// Terminal-services session id.
    pub session: Option<u32>,
    /// Working set size in KiB.
    pub rss_kb: Option<u64>,
    /// Owner account, `DOMAIN\name`, when known.
    pub user: Option<String>,
}

/// The fields `ps -o` can select, in output order given by the caller.
/// Unknown names are rejected loudly — `-o` is a contract with the script.
pub fn validate_fields(spec: &str) -> Result<Vec<String>, String> {
    const KNOWN: &[&str] = &["pid", "ppid", "name", "image", "session", "threads", "rss", "user"];
    let fields: Vec<String> = spec.split(',').map(|s| s.trim().to_lowercase()).collect();
    for f in &fields {
        if !KNOWN.contains(&f.as_str()) {
            return Err(format!("unknown field {f:?} (known: {KNOWN:?})"));
        }
    }
    if fields.is_empty() {
        return Err("empty field list".into());
    }
    Ok(fields)
}

/// Column title for a field, plus its natural width.
fn title(field: &str) -> (&'static str, usize) {
    match field {
        "pid" => ("PID", 7),
        "ppid" => ("PPID", 7),
        "name" => ("NAME", 16),
        "image" => ("IMAGE", 0),
        "session" => ("SESS", 5),
        "threads" => ("THR", 4),
        "rss" => ("RSS", 9),
        "user" => ("USER", 16),
        _ => unreachable!("validated above"),
    }
}

fn cell(rec: &ProcessRecord, field: &str) -> String {
    match field {
        "pid" => rec.pid.to_string(),
        "ppid" => rec.ppid.to_string(),
        "name" => rec.name.clone(),
        "image" => rec.image.clone().unwrap_or_default(),
        "session" => rec.session.map(|s| s.to_string()).unwrap_or_else(|| "-".into()),
        "threads" => rec.threads.to_string(),
        "rss" => rec.rss_kb.map(|s| s.to_string()).unwrap_or_else(|| "-".into()),
        "user" => rec.user.clone().unwrap_or_else(|| "-".into()),
        _ => unreachable!(),
    }
}

/// Renders the ps table: a header, then one line per process. Numeric and
/// short columns are right-aligned; name/user/image are left-aligned. A
/// zero `width` means "as wide as the content".
pub fn format_table(records: &[ProcessRecord], fields: &[String]) -> String {
    let mut out = String::new();
    let mut widths: Vec<usize> = Vec::new();
    for f in fields {
        let (t, w) = title(f);
        let mut width = w.max(t.len());
        if width == 0 {
            for r in records {
                width = width.max(cell(r, f).len());
            }
        }
        widths.push(width);
    }
    for (i, f) in fields.iter().enumerate() {
        let (t, _) = title(f);
        if i > 0 {
            out.push(' ');
        }
        // The last column is not padded: trailing whitespace on every line
        // is the kind of detail a diff tool makes you pay for.
        if i + 1 == fields.len() {
            out.push_str(t);
        } else if is_numeric(f) {
            out.push_str(&format!("{t:>width$}", width = widths[i]));
        } else {
            out.push_str(&format!("{t:<width$}", width = widths[i]));
        }
    }
    out.push('\n');
    for r in records {
        for (i, f) in fields.iter().enumerate() {
            let c = cell(r, f);
            if i > 0 {
                out.push(' ');
            }
            if i + 1 == fields.len() {
                out.push_str(&c);
            } else if is_numeric(f) {
                out.push_str(&format!("{c:>width$}", width = widths[i]));
            } else {
                out.push_str(&format!("{c:<width$}", width = widths[i]));
            }
        }
        out.push('\n');
    }
    out
}

fn is_numeric(field: &str) -> bool {
    matches!(field, "pid" | "ppid" | "session" | "threads" | "rss")
}

/// pgrep/pkill matching. The pattern is a plain substring, matched
/// case-insensitively: the OS itself does not care about case in process
/// names (one snapshot says PING.EXE, another svchost.exe), so a
/// case-sensitive match would be a coin flip, not a filter.
///
/// FreeBSD pgrep(1) takes an extended regex; without pulling a regex
/// engine into a dependency-free model, v1 matches literally and says so
/// in the usage text. `full` (pgrep -f) matches against the image path
/// instead of the exe name.
pub fn matches(record: &ProcessRecord, pattern: &str, full: bool) -> bool {
    let p = pattern.to_lowercase();
    if full {
        record
            .image
            .as_deref()
            .is_some_and(|i| i.to_lowercase().contains(&p))
    } else {
        record.name.to_lowercase().contains(&p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(pid: u32, name: &str, image: Option<&str>) -> ProcessRecord {
        ProcessRecord {
            pid,
            ppid: pid * 2,
            threads: 3,
            name: name.into(),
            image: image.map(String::from),
            session: Some(1),
            rss_kb: Some(2048),
            user: Some("ZNIE-PC\\znie".into()),
        }
    }

    #[test]
    fn field_validation() {
        assert!(validate_fields("pid,name").is_ok());
        assert!(validate_fields("PID, NAME").is_ok());
        assert!(validate_fields("pid,nonsense").is_err());
        assert!(validate_fields("").is_err());
    }

    #[test]
    fn table_has_header_and_rows() {
        let fields = validate_fields("pid,ppid,name").unwrap();
        let out = format_table(&[rec(4, "System", None), rec(100, "explorer.exe", Some(r"C:\x\explorer.exe"))], &fields);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], "    PID    PPID NAME");
        assert!(lines[1].starts_with("      4       8 System"));
        assert!(lines[2].contains("explorer.exe"));
    }

    #[test]
    fn missing_details_render_as_dashes() {
        let fields = validate_fields("pid,rss,user").unwrap();
        let empty = ProcessRecord {
            pid: 9,
            name: "x".into(),
            ..Default::default()
        };
        let out = format_table(&[empty], &fields);
        assert!(out.contains('-'));
        assert!(out.contains("  9"));
    }

    #[test]
    fn pgrep_matches_substring() {
        let r = rec(1, "explorer.exe", Some(r"C:\Windows\explorer.exe"));
        assert!(matches(&r, "explorer", false));
        assert!(matches(&r, "EXPLORER", false)); // the OS does not care
        assert!(!matches(&r, "firefox", false));
        assert!(matches(&r, "Windows", true)); // -f hits the image path
    }

    #[test]
    fn pgrep_full_requires_the_image() {
        let r = rec(1, "x", None);
        assert!(!matches(&r, "anything", true));
    }
}
