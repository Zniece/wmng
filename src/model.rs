//! ACL domain model: NFSv4 syntax, Windows values.
//!
//! The command surface is FreeBSD's NFSv4 ACL text form (setfacl(1)); the
//! values stored in every `Ace` are the native Windows ones. That split is
//! the whole design: style from UNIX, mechanisms from Windows.
//!
//! Nothing here calls Win32. Name/SID resolution is injected by the caller,
//! so the entire grammar is testable off-Windows.

/// A SID in canonical string form (`S-1-5-18`).
pub type Sid = String;

// ---------------------------------------------------------------------------
// Windows constants the model needs. Only the ones NFSv4 maps onto; the
// generic rights (GENERIC_ALL etc.) never survive in a stored ACE.
// ---------------------------------------------------------------------------

pub const FILE_READ_DATA: u32 = 0x0000_0001;
pub const FILE_WRITE_DATA: u32 = 0x0000_0002;
pub const FILE_APPEND_DATA: u32 = 0x0000_0004;
pub const FILE_READ_EA: u32 = 0x0000_0008;
pub const FILE_WRITE_EA: u32 = 0x0000_0010;
pub const FILE_EXECUTE: u32 = 0x0000_0020;
pub const FILE_DELETE_CHILD: u32 = 0x0000_0040;
pub const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
pub const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
pub const DELETE: u32 = 0x0001_0000;
pub const READ_CONTROL: u32 = 0x0002_0000;
pub const WRITE_DAC: u32 = 0x0004_0000;
pub const WRITE_OWNER: u32 = 0x0008_0000;
pub const SYNCHRONIZE: u32 = 0x0010_0000;

/// Every bit NFSv4 can express; masks are masked to this before use.
pub const FULL_SET: u32 = FILE_READ_DATA
    | FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_READ_EA
    | FILE_WRITE_EA
    | FILE_EXECUTE
    | FILE_DELETE_CHILD
    | FILE_READ_ATTRIBUTES
    | FILE_WRITE_ATTRIBUTES
    | DELETE
    | READ_CONTROL
    | WRITE_DAC
    | WRITE_OWNER
    | SYNCHRONIZE;

pub const MODIFY_SET: u32 = FULL_SET & !(WRITE_DAC | WRITE_OWNER);
pub const READ_SET: u32 = FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES | READ_CONTROL;
pub const WRITE_SET: u32 =
    FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES;

// ACE flags.
pub const OBJECT_INHERIT_ACE: u32 = 0x01;
pub const CONTAINER_INHERIT_ACE: u32 = 0x02;
pub const NO_PROPAGATE_INHERIT_ACE: u32 = 0x04;
pub const INHERIT_ONLY_ACE: u32 = 0x08;
pub const INHERITED_ACE: u32 = 0x10;
pub const SUCCESSFUL_ACCESS_ACE_FLAG: u32 = 0x40;
pub const FAILED_ACCESS_ACE_FLAG: u32 = 0x80;

/// Inheritance flags that only make sense on a directory.
pub const INHERIT_FLAGS: u32 =
    OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | NO_PROPAGATE_INHERIT_ACE | INHERIT_ONLY_ACE;

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trustee {
    /// `owner@` — the Owner Rights SID (`S-1-3-4`).
    Owner,
    /// `group@` — the object's primary group.
    PrimaryGroup,
    /// `everyone@`.
    Everyone,
    User(Sid),
    Group(Sid),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AceType {
    Allow,
    Deny,
}

impl AceType {
    pub fn as_str(self) -> &'static str {
        match self {
            AceType::Allow => "allow",
            AceType::Deny => "deny",
        }
    }
}

/// One ACE. `flags` holds Windows ACE-flag bits (including `INHERITED_ACE`
/// for entries read from a DACL — inherited entries are read-only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ace {
    pub trustee: Trustee,
    pub kind: AceType,
    pub mask: u32,
    pub flags: u32,
}

impl Ace {
    pub fn is_inherited(&self) -> bool {
        self.flags & INHERITED_ACE != 0
    }

    /// The merge/remove match key: trustee and type, nothing else. Flags are
    /// deliberately not compared — a merge overwrites them.
    pub fn same_key(&self, other: &Ace) -> bool {
        self.trustee == other.trustee && self.kind == other.kind
    }

    /// The SID this entry's trustee resolves to, given the object's primary
    /// group (for `group@`). `Owner` maps to the Owner Rights SID.
    pub fn sid<'a>(&'a self, primary_group: &'a Sid) -> &'a str {
        match &self.trustee {
            Trustee::Owner => OWNER_RIGHTS_SID,
            Trustee::PrimaryGroup => primary_group,
            Trustee::Everyone => EVERYONE_SID,
            Trustee::User(s) | Trustee::Group(s) => s,
        }
    }
}

pub const OWNER_RIGHTS_SID: &str = "S-1-3-4";
pub const EVERYONE_SID: &str = "S-1-1-0";

// ---------------------------------------------------------------------------
// Compact-form tables, in canonical output order.
// ---------------------------------------------------------------------------

/// (bit, verbose name, compact letter) — the order is the exact output
/// order of the compact permissions field.
pub const PERM_TABLE: [(u32, &str, char); 14] = [
    (FILE_READ_DATA, "read_data", 'r'),
    (FILE_WRITE_DATA, "write_data", 'w'),
    (FILE_EXECUTE, "execute", 'x'),
    (FILE_APPEND_DATA, "append_data", 'p'),
    (FILE_DELETE_CHILD, "delete_child", 'D'),
    (DELETE, "delete", 'd'),
    (FILE_READ_ATTRIBUTES, "read_attributes", 'a'),
    (FILE_WRITE_ATTRIBUTES, "write_attributes", 'A'),
    (FILE_READ_EA, "read_xattr", 'R'),
    (FILE_WRITE_EA, "write_xattr", 'W'),
    (READ_CONTROL, "read_acl", 'c'),
    (WRITE_DAC, "write_acl", 'C'),
    (WRITE_OWNER, "write_owner", 'o'),
    (SYNCHRONIZE, "synchronize", 's'),
];

/// (bit, verbose name, compact letter) for the flags field.
pub const FLAG_TABLE: [(u32, &str, char); 7] = [
    (OBJECT_INHERIT_ACE, "file_inherit", 'f'),
    (CONTAINER_INHERIT_ACE, "dir_inherit", 'd'),
    (INHERIT_ONLY_ACE, "inherit_only", 'i'),
    (NO_PROPAGATE_INHERIT_ACE, "no_propagate", 'n'),
    (SUCCESSFUL_ACCESS_ACE_FLAG, "successfull_access", 'S'),
    (FAILED_ACCESS_ACE_FLAG, "failed_access", 'F'),
    (INHERITED_ACE, "inherited", 'I'),
];

// ---------------------------------------------------------------------------
// Field parse/format
// ---------------------------------------------------------------------------

/// Parses a permissions or flags field.
///
/// Verbose form first: every `/`-separated token must be a long name (a
/// set name counts). If any token is not, the whole field is re-read as
/// the compact form: one letter per character, `-` meaning "absent". An
/// empty field is zero. This is FreeBSD's two-pass order, and it is order
/// that makes `read_data/execute` and `rx` both valid while `rx/` cannot
/// silently half-parse.
fn parse_bitfield(
    text: &str,
    table: &[(u32, &str, char)],
    sets: &[(u32, &str)],
) -> Result<u32, String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(0);
    }

    let tokens: Vec<&str> = trimmed
        .split('/')
        .filter(|t| !t.is_empty() && *t != "-")
        .collect();
    let mut value = 0u32;
    let mut all_names = !tokens.is_empty();
    for tok in &tokens {
        let mut found = false;
        for &(bit, name, _) in table {
            if *tok == name {
                value |= bit;
                found = true;
            }
        }
        if !found {
            for &(bit, name) in sets {
                if *tok == name {
                    value |= bit;
                    found = true;
                }
            }
        }
        if !found {
            all_names = false;
            break;
        }
    }
    if all_names {
        return Ok(value);
    }

    let mut value = 0u32;
    for ch in trimmed.chars() {
        if ch == '-' {
            continue;
        }
        match table.iter().find(|&&(_, _, l)| l == ch) {
            Some(&(bit, _, _)) => value |= bit,
            None => return Err(format!("invalid flag or permission \"{ch}\" in \"{trimmed}\"")),
        }
    }
    Ok(value)
}

/// Formats a bitfield in compact form: one slot per table entry, `-` when
/// the bit is clear.
fn format_bits_compact(mut value: u32, table: &[(u32, &str, char)]) -> String {
    let mut out = String::new();
    for &(bit, _, letter) in table {
        if value & bit != 0 {
            out.push(letter);
            value &= !bit;
        } else {
            out.push('-');
        }
    }
    out
}

/// Formats a bitfield in verbose form: long names joined by `/`.
fn format_bits_verbose(mut value: u32, table: &[(u32, &str, char)]) -> String {
    let mut names = Vec::new();
    for &(bit, name, _) in table {
        if value & bit != 0 {
            names.push(name);
            value &= !bit;
        }
    }
    names.join("/")
}

pub fn parse_perm_field(text: &str) -> Result<u32, String> {
    parse_bitfield(text, &PERM_TABLE, &[(FULL_SET, "full_set"), (MODIFY_SET, "modify_set"), (READ_SET, "read_set"), (WRITE_SET, "write_set")])
        .map(|v| v & FULL_SET)
}

pub fn parse_flag_field(text: &str) -> Result<u32, String> {
    let all = OBJECT_INHERIT_ACE
        | CONTAINER_INHERIT_ACE
        | NO_PROPAGATE_INHERIT_ACE
        | INHERIT_ONLY_ACE
        | INHERITED_ACE
        | SUCCESSFUL_ACCESS_ACE_FLAG
        | FAILED_ACCESS_ACE_FLAG;
    parse_bitfield(text, &FLAG_TABLE, &[]).map(|v| v & all)
}

pub fn format_mask(mask: u32, verbose: bool) -> String {
    if verbose {
        format_bits_verbose(mask, &PERM_TABLE)
    } else {
        format_bits_compact(mask, &PERM_TABLE)
    }
}

pub fn format_flags(flags: u32, verbose: bool) -> String {
    if verbose {
        format_bits_verbose(flags, &FLAG_TABLE)
    } else {
        format_bits_compact(flags, &FLAG_TABLE)
    }
}

// ---------------------------------------------------------------------------
// Entry grammar
// ---------------------------------------------------------------------------

/// How a name/SID qualifier resolves, injected by the applet. Returns the
/// canonical SID, or `None` when the name is unknown (in which case an
/// appended-id field becomes mandatory, mirroring FreeBSD).
pub trait ResolveNames {
    fn resolve(&mut self, qualifier: &str) -> Option<Sid>;
}

/// Parse errors carry the offending fragment; the applet prefixes them with
/// the entry text and the file name.
pub type EntryError = String;

/// Parses ONE ACL entry (no commas, no comments — those are stripped by
/// `parse_acl_text`).
///
/// Grammar, per FreeBSD `_nfs4_acl_entry_from_text`:
///
/// ```text
/// tag[:qualifier]:perms[:flags]:type[::<appended id>]
/// ```
///
/// `user`/`group` need a qualifier (a name, `*S-1-…` raw SID, or — when
/// the name cannot be resolved — the appended id at the end of the line).
pub fn parse_entry(text: &str, resolver: &mut dyn ResolveNames) -> Result<Ace, EntryError> {
    let fields: Vec<&str> = text.split(':').collect();

    let tag = fields.first().copied().unwrap_or("").trim();
    let (trustee_tag, need_qualifier) = match tag {
        "owner@" => (Tag::Owner, false),
        "group@" => (Tag::Group, false),
        "everyone@" => (Tag::Everyone, false),
        "user" | "u" => (Tag::User, true),
        "group" | "g" => (Tag::Group, true),
        _ => return Err("invalid \"tag\" field".into()),
    };

    let mut i = 1;
    let mut qualifier_unresolved = false;
    let mut qualifier_text = String::new();
    if need_qualifier {
        let q = fields.get(i).ok_or("truncated ACL entry")?.trim();
        if q.is_empty() {
            return Err("empty \"qualifier\" field".into());
        }
        qualifier_text = q.to_string();
        i += 1;
        if let Some(rest) = q.strip_prefix('*') {
            // icacls convention: a raw SID, never name-resolved.
            qualifier_unresolved = false;
            qualifier_text = rest.to_string();
        } else {
            match resolver.resolve(q) {
                Some(sid) => {
                    qualifier_text = sid;
                    qualifier_unresolved = false;
                }
                None => {
                    qualifier_unresolved = true;
                }
            }
        }
    }

    let perms_field: &str = *fields.get(i).ok_or("truncated ACL entry")?;
    i += 1;
    let mask = parse_perm_field(perms_field)?;

    // A flags field is present iff anything follows beyond the type.
    let has_flags = fields.len() > i + 1;
    let flags = if has_flags {
        let f: &str = fields[i];
        i += 1;
        parse_flag_field(f)?
    } else {
        0
    };

    let type_field: &str = *fields.get(i).ok_or("truncated ACL entry")?;
    i += 1;
    let kind = match type_field {
        "allow" => AceType::Allow,
        "deny" => AceType::Deny,
        "audit" | "alarm" => {
            // FreeBSD stores these as system audit/alarm entries. On
            // Windows they live in the SACL, which v1 does not touch;
            // accepting them would be a silent no-op, so refuse.
            return Err(format!(
                "\"{type_field}\" entries require the SACL, which is not implemented"
            ));
        }
        _ => return Err("invalid \"type\" field".into()),
    };

    if need_qualifier && qualifier_unresolved {
        // FreeBSD: an unresolvable name must carry an appended numeric id.
        // Ours is the appended SID.
        let sid = fields.get(i).ok_or_else(|| {
            format!("unknown user or group name \"{qualifier_text}\" (an appended SID is required to restore it)")
        })?;
        let sid = sid.trim();
        if !is_sid(sid) {
            return Err(format!("appended id \"{sid}\" is not a SID"));
        }
        qualifier_text = sid.to_string();
    }

    let trustee = match trustee_tag {
        Tag::Owner => Trustee::Owner,
        Tag::Group if !need_qualifier => Trustee::PrimaryGroup,
        Tag::Everyone => Trustee::Everyone,
        // Canonicalise the two SIDs that have their own tags: whatever
        // spelling arrived on the command line, the same SID must always
        // compare equal to itself on a later merge.
        Tag::User if qualifier_text == OWNER_RIGHTS_SID => Trustee::Owner,
        Tag::Group if qualifier_text == OWNER_RIGHTS_SID => Trustee::Owner,
        Tag::User | Tag::Group if qualifier_text == EVERYONE_SID => Trustee::Everyone,
        Tag::User => Trustee::User(qualifier_text),
        Tag::Group => Trustee::Group(qualifier_text),
    };

    // The INHERITED flag is kept here: it distinguishes entries that
    // DESCRIBE inherited ACEs (round-tripped getfacl output) from real
    // explicit requests. merge() decides what each kind means; a bare
    // explicit entry has the bit stripped on insert, because only Windows
    // gets to say an ACE is inherited.
    Ok(Ace {
        trustee,
        kind,
        mask,
        flags,
    })
}

enum Tag {
    Owner,
    Group,
    Everyone,
    User,
}

/// Recognises the `S-1-…` string form well enough to catch typos. Only the
/// shape is checked; whether the authority exists is the resolver's business.
pub fn is_sid(s: &str) -> bool {
    let mut parts = s.splitn(2, '-');
    parts.next() == Some("S") && {
        let Some(rest) = parts.next() else { return false };
        let mut sub = rest.split('-');
        sub.next() == Some("1")
            && sub.next().is_some_and(|r| r.parse::<u32>().is_ok())
            && sub.any(|r| r.parse::<u64>().is_ok())
    }
}

/// Options for rendering one `getfacl` line.
///
/// Which SIDs render as `group@` is decided when the ACL is READ: the
/// provider compares each ACE's SID against the object's primary group and
/// emits `Trustee::PrimaryGroup` only for that one. Here it always means group@.
/// always `group@`.
#[derive(Clone)]
pub struct FormatOpts<'a> {
    /// `-n`: print SIDs instead of account names.
    pub numeric: bool,
    /// `-v`: verbose long names.
    pub verbose: bool,
    /// `-i`: append the SID after user/group entries.
    pub append_id: bool,
    /// Turns a SID into a display name (`DOMAIN\name`), or the SID text if
    /// unknown. Injected by the applet; a mock serves the tests.
    pub sid_to_name: &'a dyn Fn(&str) -> String,
}

impl Default for FormatOpts<'_> {
    fn default() -> Self {
        FormatOpts {
            numeric: false,
            verbose: false,
            append_id: false,
            sid_to_name: &|s| s.to_string(),
        }
    }
}

/// Renders one entry, exactly in the FreeBSD text form:
///
/// ```text
///             owner@:rwxp--aARWcCos:-------:allow
/// ```
///
/// The who field is right-aligned to width 18.
pub fn format_entry(ace: &Ace, opts: &FormatOpts) -> String {
    let (who, has_id): (String, Option<&Sid>) = match &ace.trustee {
        Trustee::Owner => ("owner@".to_string(), None),
        Trustee::PrimaryGroup => ("group@".to_string(), None),
        Trustee::Everyone => ("everyone@".to_string(), None),
        Trustee::User(sid) => (format!("user:{}", (opts.sid_to_name)(sid)), Some(sid)),
        Trustee::Group(sid) => (format!("group:{}", (opts.sid_to_name)(sid)), Some(sid)),
    };
    let mut out = format!("{who:>18}:");
    out.push_str(&format_mask(ace.mask, opts.verbose));
    out.push(':');
    out.push_str(&format_flags(ace.flags, opts.verbose));
    out.push(':');
    out.push_str(ace.kind.as_str());
    if opts.append_id {
        if let Some(sid) = has_id {
            out.push(':');
            out.push_str(sid);
        }
    }
    out
}

/// Parses ACL text into entries: lines on `\n`, `#` comments stripped,
/// entries split on `,`, empty pieces skipped. This is the grammar that
/// makes `getfacl a | setfacl -M - b` work.
pub fn parse_acl_text(text: &str, resolver: &mut dyn ResolveNames) -> Result<Vec<Ace>, EntryError> {
    let mut out = Vec::new();
    for line in text.split('\n') {
        let line = line.split('#').next().unwrap_or("");
        for entry in line.split(',') {
            if entry.trim().is_empty() {
                continue;
            }
            out.push(parse_entry(entry, resolver)?);
        }
    }
    Ok(out)
}


#[cfg(test)]
mod tests {
    use super::*;

    struct Mock;
    impl ResolveNames for Mock {
        fn resolve(&mut self, q: &str) -> Option<Sid> {
            // Windows account lookup is case-insensitive; so is the mock.
            match q.to_ascii_lowercase().as_str() {
                "everyone" => Some(EVERYONE_SID.into()),
                "owner_rights" => Some(OWNER_RIGHTS_SID.into()),
                _ => Some(format!("S-1-5-{q}")),
            }
        }
    }

    struct NoResolve;
    impl ResolveNames for NoResolve {
        fn resolve(&mut self, _: &str) -> Option<Sid> {
            None
        }
    }

    fn parse(text: &str) -> Result<Ace, String> {
        parse_entry(text, &mut Mock)
    }

    #[test]
    fn compact_perm_letters_round_trip() {
        let mask = parse_perm_field("rwxpDdaARWcCos").unwrap();
        assert_eq!(mask, FULL_SET);
        assert_eq!(format_mask(mask, false), "rwxpDdaARWcCos");
    }

    #[test]
    fn the_freebsd_canonical_example_renders_exactly() {
        // From ACL-PORT-SPEC §5 — the reference output line.
        let mask = FILE_READ_DATA
            | FILE_EXECUTE
            | FILE_READ_ATTRIBUTES
            | FILE_READ_EA
            | READ_CONTROL
            | SYNCHRONIZE;
        let ace = Ace {
            trustee: Trustee::Owner,
            kind: AceType::Allow,
            mask,
            flags: 0,
        };
        let opts = FormatOpts::default();
        assert_eq!(
            format_entry(&ace, &opts),
            "            owner@:r-x---a-R-c--s:-------:allow"
        );
        // The spec's owner line: rwxp--aARWcCos
        let ace = Ace {
            trustee: Trustee::Owner,
            kind: AceType::Allow,
            mask: FILE_READ_DATA
                | FILE_WRITE_DATA
                | FILE_EXECUTE
                | FILE_APPEND_DATA
                | FILE_READ_ATTRIBUTES
                | FILE_WRITE_ATTRIBUTES
                | FILE_READ_EA
                | FILE_WRITE_EA
                | READ_CONTROL
                | WRITE_DAC
                | WRITE_OWNER
                | SYNCHRONIZE,
            flags: 0,
        };
        assert_eq!(
            format_entry(&ace, &opts),
            "            owner@:rwxp--aARWcCos:-------:allow"
        );
    }

    #[test]
    fn perm_dashes_and_empty_are_valid() {
        assert_eq!(parse_perm_field("----").unwrap(), 0);
        assert_eq!(parse_perm_field("").unwrap(), 0);
        assert_eq!(parse_perm_field("-").unwrap(), 0);
    }

    #[test]
    fn verbose_perm_names_parse() {
        let m = parse_perm_field("read_data/write_data").unwrap();
        assert_eq!(m, FILE_READ_DATA | FILE_WRITE_DATA);
        assert_eq!(format_mask(m, true), "read_data/write_data");
    }

    #[test]
    fn perm_sets_parse() {
        assert_eq!(parse_perm_field("full_set").unwrap(), FULL_SET);
        assert_eq!(parse_perm_field("read_set").unwrap(), READ_SET);
        assert_eq!(parse_perm_field("write_set").unwrap(), WRITE_SET);
        assert_eq!(
            parse_perm_field("modify_set").unwrap(),
            FULL_SET & !(WRITE_DAC | WRITE_OWNER)
        );
    }

    #[test]
    fn unknown_perm_letter_is_an_error() {
        assert!(parse_perm_field("rq").is_err());
    }

    #[test]
    fn flags_parse_and_format() {
        assert_eq!(
            parse_flag_field("fd").unwrap(),
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
        );
        assert_eq!(parse_flag_field("file_inherit/no_propagate").unwrap(),
            OBJECT_INHERIT_ACE | NO_PROPAGATE_INHERIT_ACE);
        assert_eq!(format_flags(INHERITED_ACE, false), "------I");
        assert_eq!(format_flags(0, false), "-------");
        assert_eq!(format_flags(OBJECT_INHERIT_ACE, true), "file_inherit");
    }

    #[test]
    fn entry_parse_full_grammar() {
        let ace = parse("owner@:rwxpDdaARWcCos:fd:allow").unwrap();
        assert_eq!(ace.trustee, Trustee::Owner);
        assert_eq!(ace.kind, AceType::Allow);
        assert_eq!(ace.mask, FULL_SET);
        assert_eq!(ace.flags, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE);

        let ace = parse("user:znie:rwx:allow").unwrap();
        assert_eq!(ace.trustee, Trustee::User("S-1-5-znie".into()));
        assert_eq!(ace.mask, FILE_READ_DATA | FILE_WRITE_DATA | FILE_EXECUTE);

        let ace = parse("group:Users:rx:deny").unwrap();
        assert_eq!(ace.trustee, Trustee::Group("S-1-5-Users".into()));
        assert_eq!(ace.kind, AceType::Deny);

        // Short tag spellings.
        assert_eq!(parse("u:znie:r:allow").unwrap().trustee, Trustee::User("S-1-5-znie".into()));
        assert_eq!(parse("g:Users:r:allow").unwrap().trustee, Trustee::Group("S-1-5-Users".into()));
    }

    #[test]
    fn three_field_entries_have_no_flags() {
        let ace = parse("everyone@:r:allow").unwrap();
        assert_eq!(ace.flags, 0);
        assert_eq!(ace.trustee, Trustee::Everyone);
    }

    #[test]
    fn starred_sid_qualifier_never_resolves() {
        // The '*' form is taken literally by the model itself; a resolver
        // that resolves nothing must still accept it. Plain SID text is the
        // resolver's business (the applet's resolver recognises it).
        let ace = parse_entry("user:*S-1-5-18:r:allow", &mut NoResolve).unwrap();
        assert_eq!(ace.trustee, Trustee::User("S-1-5-18".into()));
    }

    #[test]
    fn unresolved_name_requires_appended_sid() {
        // Without an appended SID the entry is malformed — FreeBSD demands
        // the numeric id; ours demands the SID.
        assert!(parse_entry("user:ghost:r:allow", &mut NoResolve).is_err());
        // FreeBSD spelling: the appended id rides behind the type, and the
        // entry must carry a flags field for the grammar to be unambiguous.
        let ace = parse_entry("user:ghost:r:-:allow:S-1-5-999", &mut NoResolve).unwrap();
        assert_eq!(ace.trustee, Trustee::User("S-1-5-999".into()));
    }

    #[test]
    fn audit_and_alarm_are_refused() {
        assert!(parse("owner@:r:audit").is_err());
        assert!(parse("owner@:r:alarm").is_err());
    }

    #[test]
    fn inherited_flag_survives_parse() {
        // merge() needs to see it to recognise round-tripped inherited
        // entries; an explicit insert strips it afterwards.
        let ace = parse("owner@:r:I:allow").unwrap();
        assert_eq!(ace.flags, INHERITED_ACE);
    }

    #[test]
    fn truncated_entries_are_errors() {
        assert!(parse("owner@").is_err());
        assert!(parse("owner@:rwx").is_err());
        assert!(parse("user::r:allow").is_err());
        assert!(parse("nobody@:r:allow").is_err());
    }

    #[test]
    fn acl_text_splits_lines_commas_and_comments() {
        let text = "# file: a\n# owner: root\nowner@:r:allow, everyone@:w:deny\n# tail comment\n\n";
        let aces = parse_acl_text(text, &mut Mock).unwrap();
        assert_eq!(aces.len(), 2);
        assert_eq!(aces[0].trustee, Trustee::Owner);
        assert_eq!(aces[1].kind, AceType::Deny);
    }

    #[test]
    fn getfacl_output_round_trips_through_parse() {
        // The pipeline getfacl | setfacl -M - depends on every line of
        // this output parsing cleanly.
        let ace = Ace {
            trustee: Trustee::User("S-1-5-1000".into()),
            kind: AceType::Allow,
            mask: READ_SET,
            flags: INHERITED_ACE,
        };
        let opts = FormatOpts {
            append_id: true,
            ..Default::default()
        };
        let line = format_entry(&ace, &opts);
        let parsed = parse_entry(line.trim(), &mut NoResolve).unwrap();
        assert_eq!(parsed.trustee, Trustee::User("S-1-5-1000".into()));
        assert_eq!(parsed.mask, READ_SET);
        // The I flag is preserved: this input entry DESCRIBES an inherited
        // ACE, and only merge() can tell what that means here.
        assert_eq!(parsed.flags, INHERITED_ACE);
    }

    #[test]
    fn format_appends_the_sid_only_for_qualified_entries() {
        let opts = FormatOpts {
            append_id: true,
            ..Default::default()
        };
        let owner = Ace {
            trustee: Trustee::Owner,
            kind: AceType::Allow,
            mask: READ_SET,
            flags: 0,
        };
        // No fifth field: the line ends at the type.
        assert_eq!(format_entry(&owner, &opts).split(':').count(), 4);
        let user = Ace {
            trustee: Trustee::User("S-1-5-9".into()),
            kind: AceType::Allow,
            mask: READ_SET,
            flags: 0,
        };
        assert!(format_entry(&user, &opts).ends_with(":allow:S-1-5-9"));
    }

    #[test]
    fn numeric_mode_prints_the_sid() {
        let opts = FormatOpts {
            numeric: true,
            ..Default::default()
        };
        let ace = Ace {
            trustee: Trustee::User("S-1-5-9".into()),
            kind: AceType::Allow,
            mask: 0,
            flags: 0,
        };
        // sid_to_name defaults to the SID text, so numeric and default
        // renderings agree for unknown SIDs.
        assert_eq!(
            format_entry(&ace, &opts),
            format_entry(&ace, &FormatOpts::default())
        );
    }

    #[test]
    fn special_sids_canonicalise_to_their_tags() {
        // user:Everyone, group:Everyone and everyone@ must all merge into
        // the same entry.
        let a = parse("user:everyone:r:allow").unwrap();
        let b = parse("group:Everyone:r:allow").unwrap();
        let c = parse("everyone@:r:allow").unwrap();
        assert_eq!(a.trustee, Trustee::Everyone);
        assert_eq!(b.trustee, Trustee::Everyone);
        assert_eq!(c.trustee, Trustee::Everyone);
        assert_eq!(parse("user:*S-1-3-4:r:allow").unwrap().trustee, Trustee::Owner);
    }

    #[test]
    fn sid_shape_checks() {
        assert!(is_sid("S-1-5-18"));
        assert!(is_sid("S-1-5-21-100-200-500-1001"));
        assert!(!is_sid("S-x-5"));
        assert!(!is_sid("znie"));
        assert!(!is_sid("S-1"));
    }
}
