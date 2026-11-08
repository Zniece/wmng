//! Win32 bindings for security descriptors: the ONLY place in wmng that
//! calls Windows. Everything above this line is portable model code.
//!
//! Reading: `GetNamedSecurityInfoW` (follows reparse points) or
//! `GetSecurityInfo` on a handle opened with `FILE_FLAG_OPEN_REPARSE_POINT`
//! (for `-h`, which must not follow). Writing: `SetNamedSecurityInfoW`,
//! passing only the DACL so owner and SACL cannot be clobbered.
//!
//! The DACL is rebuilt by hand rather than through `SetEntriesInAclW`:
//! that API merges by its own rules and would silently reorder or dedupe
//! entries, while the whole point of the model layer is that WE decide the
//! order (deny-before-allow, explicit-before-inherited).

#![allow(non_snake_case)]

use wmng_model::model::{
    Ace, AceType, Sid, Trustee, EVERYONE_SID, INHERITED_ACE, OWNER_RIGHTS_SID, READ_CONTROL,
};

use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSidToSidW, GetNamedSecurityInfoW, GetSecurityInfo,
    SetNamedSecurityInfoW, SetSecurityInfo, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    GetAce, GetAclInformation, LookupAccountNameW, LookupAccountSidW, ACL, ACL_REVISION_DS,
    ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PSID, SID_NAME_USE, AclSizeInformation,
};
use super::{from_wide, last_error, to_wide, win_path, WinErr};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, OPEN_EXISTING,
};

// The model defines NFSv4-mapped rights with Windows values; those same
// bits are what a stored ACE carries. Specific rights not in the NFSv4
// table (e.g. FILE_WRITE_DAC-as-generic leftovers) are preserved verbatim.
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;

// ---------------------------------------------------------------------------
// SID <-> string, name resolution
// ---------------------------------------------------------------------------

pub fn sid_to_string(sid: PSID) -> Option<Sid> {
    let mut out = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut out) } == 0 {
        return None;
    }
    let s = from_wide(unsafe { wide_ptr(out) });
    unsafe { LocalFree(out as _) };
    Some(s)
}

/// Reads a NUL-terminated wide string from a raw pointer.
unsafe fn wide_ptr<'a>(p: *const u16) -> &'a [u16] {
    let mut len = 0usize;
    while *p.add(len) != 0 {
        len += 1;
    }
    std::slice::from_raw_parts(p, len)
}

pub fn sid_from_string(s: &str) -> Option<(PSID, Vec<u16>)> {
    // The wide buffer must outlive the SID use; the API does not document
    // whether the SID may alias the input, so keep both alive together.
    let w = to_wide(s);
    let mut sid: PSID = std::ptr::null_mut();
    if unsafe { ConvertStringSidToSidW(w.as_ptr(), &mut sid) } == 0 {
        return None;
    }
    Some((sid, w))
}

/// True for the account kinds that render as `group:NAME`; anything else
/// (plain user, computer, well-known principal) renders as `user:NAME`.
///
/// Well-known principals (SidTypeWellKnownGroup) are deliberately NOT
/// groups here: `NT AUTHORITY\SYSTEM` reports as a well-known group, and
/// labelling it `group:` would only confuse. Only real groups and aliases
/// (the SAM groups an admin manages) count.
fn sid_use_is_group(u: SID_NAME_USE) -> bool {
    // 2 = group, 4 = alias
    matches!(u, 2 | 4)
}

/// (SID string, is_group) for an account name, or None when unknown.
pub fn lookup_name(name: &str) -> Option<(Sid, bool)> {
    let sys = std::ptr::null();
    let account = to_wide(name);
    let mut sid_buf = vec![0u16; 256];
    let mut domain_buf = vec![0u16; 256];
    let mut domain_len = domain_buf.len() as u32;
    let mut use_ = 0i32;
    let ok = unsafe {
        LookupAccountNameW(
            sys,
            account.as_ptr(),
            sid_buf.as_mut_ptr() as PSID,
            &mut (sid_buf.len() as u32),
            domain_buf.as_mut_ptr(),
            &mut domain_len,
            &mut use_,
        )
    };
    if ok == 0 {
        return None;
    }
    let sid = sid_to_string(sid_buf.as_ptr() as PSID)?;
    Some((sid, sid_use_is_group(use_)))
}

/// (DOMAIN\name or SID text, is_group) for a SID.
pub fn lookup_sid(sid: &str) -> (String, bool) {
    let Some((psid, _w)) = sid_from_string(sid) else {
        return (sid.to_string(), false);
    };
    let mut name_buf = vec![0u16; 256];
    let mut domain_buf = vec![0u16; 256];
    let mut domain_len = domain_buf.len() as u32;
    let mut use_ = 0i32;
    let ok = unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            psid,
            name_buf.as_mut_ptr(),
            &mut (name_buf.len() as u32),
            domain_buf.as_mut_ptr(),
            &mut domain_len,
            &mut use_,
        )
    };
    let out = if ok == 0 {
        (sid.to_string(), false)
    } else {
        let name = from_wide(&name_buf);
        let domain = from_wide(&domain_buf[..domain_len as usize]);
        let full = if domain.is_empty() {
            name
        } else {
            format!("{domain}\\{name}")
        };
        (full, sid_use_is_group(use_))
    };
    unsafe { LocalFree(psid as _) };
    out
}

// ---------------------------------------------------------------------------
// Reading a DACL
// ---------------------------------------------------------------------------

/// One raw ACE we could not translate into the model (object-inherit or
/// audit ACE types on a file system object). Kept byte-for-byte so a
/// read-modify-write never destroys one; `getfacl` prints a marker line.
#[derive(Clone)]
pub struct RawAce {
    pub bytes: Vec<u8>,
    pub inherited: bool,
}

/// The full security picture of one object.
pub struct Sd {
    pub owner: Sid,
    pub group: Sid,
    pub aces: Vec<Ace>,
    pub raw: Vec<RawAce>,
    /// True when the SD has no DACL at all, which Windows reads as
    /// "allow everyone full control" — different from an EMPTY DACL, which
    /// denies everyone. getfacl prints it explicitly.
    pub no_dacl: bool,
}

/// Reads owner, primary group and DACL of `path`.
///
/// `follow=false` opens the object itself with
/// `FILE_FLAG_OPEN_REPARSE_POINT` (the `-h` path); the named APIs cannot be
/// told to do that, so it goes through a handle.
pub fn read_sd(path: &str, follow: bool) -> Result<Sd, String> {
    let mut owner: PSID = std::ptr::null_mut();
    let mut group: PSID = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd = std::ptr::null_mut();

    let rc = if follow {
        let w = to_wide(&win_path(path));
        unsafe {
            GetNamedSecurityInfoW(
                w.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION
                    | GROUP_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION,
                &mut owner,
                &mut group,
                &mut dacl,
                std::ptr::null_mut(),
                &mut sd,
            )
        }
    } else {
        let handle = open_handle(path, READ_CONTROL)?;
        let rc = unsafe {
            GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION
                    | GROUP_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION,
                &mut owner,
                &mut group,
                &mut dacl,
                std::ptr::null_mut(),
                &mut sd,
            )
        };
        unsafe { CloseHandle(handle) };
        rc
    };
    if rc != 0 {
        return Err(WinErr(rc as u32).to_string());
    }

    let owner_sid = sid_to_string(owner).unwrap_or_default();
    let group_sid = sid_to_string(group).unwrap_or_default();

    let out = if dacl.is_null() {
        Sd {
            owner: owner_sid,
            group: group_sid,
            aces: Vec::new(),
            raw: Vec::new(),
            no_dacl: true,
        }
    } else {
        parse_dacl(dacl, &owner_sid, &group_sid)
    };

    if !sd.is_null() {
        unsafe { LocalFree(sd as _) };
    }
    Ok(out)
}

fn parse_dacl(dacl: *mut ACL, owner: &str, group: &str) -> Sd {
    let mut info = ACL_SIZE_INFORMATION {
        AceCount: 0,
        AclBytesInUse: 0,
        AclBytesFree: 0,
    };
    let ok = unsafe {
        GetAclInformation(
            dacl,
            &mut info as *mut _ as *mut core::ffi::c_void,
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    };
    let count = if ok != 0 { info.AceCount } else { 0 };

    let mut aces = Vec::new();
    let mut raw = Vec::new();
    for i in 0..count {
        let mut ace_ptr: *mut core::ffi::c_void = std::ptr::null_mut();
        if unsafe { GetAce(dacl, i as u32, &mut ace_ptr) } == 0 {
            continue;
        }
        let bytes = unsafe { std::slice::from_raw_parts(ace_ptr as *const u8, ace_size(ace_ptr)) };
        match decode_ace(bytes, owner, group) {
            Some(ace) => aces.push(ace),
            None => raw.push(RawAce {
                bytes: bytes.to_vec(),
                inherited: bytes[1] as u32 & INHERITED_ACE != 0,
            }),
        }
    }
    Sd {
        owner: owner.to_string(),
        group: group.to_string(),
        aces,
        raw,
        no_dacl: false,
    }
}

/// ACE header size = 4; AceSize lives at offset 2.
unsafe fn ace_size(p: *mut core::ffi::c_void) -> usize {
    let b = p as *const u8;
    *b.add(2) as usize | ((*b.add(3) as usize) << 8)
}

/// Translates allow/deny ACEs with a known SID into the model. ACEs whose
/// type is not allow/deny are left raw by returning None.
fn decode_ace(bytes: &[u8], owner: &str, group: &str) -> Option<Ace> {
    if bytes.len() < 8 {
        return None;
    }
    let kind = match bytes[0] {
        x if x == ACCESS_ALLOWED_ACE_TYPE => AceType::Allow,
        x if x == ACCESS_DENIED_ACE_TYPE => AceType::Deny,
        _ => return None,
    };
    let flags = bytes[1] as u32;
    let mask = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let sid_bytes = &bytes[8..];
    let sid = sid_bytes_to_string(sid_bytes)?;

    // NFSv4 tags: owner@ is the Owner Rights SID; group@ is whatever the
    // object's primary group is. Decided here, on read, because only the
    // reader knows the primary group.
    let trustee = if sid == OWNER_RIGHTS_SID {
        Trustee::Owner
    } else if sid == group && !group.is_empty() {
        Trustee::PrimaryGroup
    } else if sid == EVERYONE_SID {
        Trustee::Everyone
    } else {
        let (_, is_group) = lookup_sid(&sid);
        if is_group {
            Trustee::Group(sid)
        } else {
            Trustee::User(sid)
        }
    };
    let _ = owner;
    Some(Ace {
        trustee,
        kind,
        mask,
        flags,
    })
}

/// Renders a binary SID into `S-1-…` without the conversion API (it takes a
/// PSID, and here we only have bytes copied out of an ACE).
fn sid_bytes_to_string(b: &[u8]) -> Option<String> {
    // SID: revision(1) subauthority-count(1) identifier-authority(6) then
    // 4-byte little-endian subauthorities.
    if b.len() < 8 {
        return None;
    }
    let revision = b[0];
    if revision != 1 {
        return None;
    }
    let count = b[1] as usize;
    if b.len() < 8 + count * 4 {
        return None;
    }
    let auth = u64::from_be_bytes([0, 0, b[2], b[3], b[4], b[5], b[6], b[7]]);
    let mut s = format!("S-{revision}-{auth}");
    for i in 0..count {
        let off = 8 + i * 4;
        let sub = u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]]);
        s.push_str(&format!("-{sub}"));
    }
    Some(s)
}

// ---------------------------------------------------------------------------
// Writing a DACL
// ---------------------------------------------------------------------------

/// Opens a handle for the handle-based security APIs.
/// `access` is e.g. READ_CONTROL (read) or FILE_WRITE_DAC|READ_CONTROL
/// (read-modify-write).
fn open_handle(path: &str, access: u32) -> Result<HANDLE, String> {
    let w = to_wide(&win_path(path));
    let handle = unsafe {
        CreateFileW(
            w.as_ptr(),
            access,
            1 | 2, // FILE_SHARE_READ | FILE_SHARE_WRITE
            std::ptr::null(),
            OPEN_EXISTING as u32,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle as isize == -1 || handle.is_null() {
        return Err(last_error().to_string());
    }
    Ok(handle)
}

/// Serialises model ACEs (plus raw pass-throughs) into an ACL allocation.
///
/// Layout: ACL header { revision, 0, size:u16, count:u16, 0 } then ACEs.
/// Order is the caller's: explicit section first (deny before allow — the
/// model canonicalises), then inherited entries in their original order.
pub fn build_acl(explicit: &[Ace], raw_explicit: &[RawAce], inherited: &[Ace], raw_inherited: &[RawAce]) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    buf.resize(8, 0); // ACL header, filled in at the end

    let mut count = 0u16;
    for ace in explicit.iter().chain(inherited.iter()) {
        let Some((psid, _w)) = sid_from_string(ace_sid(ace)) else {
            continue; // unserialisable trustee: skip rather than corrupt
        };
        unsafe {
            let sid_len = sid_length(psid) as usize;
            let ace_size = 8 + sid_len;
            buf.reserve(ace_size);
            let start = buf.len();
            buf.push(if matches!(ace.kind, AceType::Allow) { ACCESS_ALLOWED_ACE_TYPE } else { ACCESS_DENIED_ACE_TYPE });
            buf.push(ace.flags as u8);
            buf.extend_from_slice(&(ace_size as u16).to_le_bytes());
            buf.extend_from_slice(&ace.mask.to_le_bytes());
            let sid_bytes = std::slice::from_raw_parts(psid as *const u8, sid_len);
            buf.extend_from_slice(sid_bytes);
            debug_assert_eq!(buf.len() - start, ace_size);
            LocalFree(psid as _);
        }
        count += 1;
    }
    for r in raw_explicit.iter().chain(raw_inherited.iter()) {
        buf.extend_from_slice(&r.bytes);
        count += 1;
    }

    let total = buf.len() as u16;
    buf[0] = ACL_REVISION_DS as u8;
    buf[2..4].copy_from_slice(&total.to_le_bytes());
    buf[4..6].copy_from_slice(&count.to_le_bytes());
    buf
}

/// Length in bytes of a binary SID (8 + 4 × subauthorities).
unsafe fn sid_length(psid: PSID) -> u32 {
    let b = psid as *const u8;
    8 + (*b.add(1) as u32) * 4
}

/// The SID an entry's trustee refers to. `group@` needs the object's
/// primary group — the caller supplies it via `sd_group`.
fn ace_sid(ace: &Ace) -> &str {
    match &ace.trustee {
        Trustee::Owner => OWNER_RIGHTS_SID,
        Trustee::Everyone => EVERYONE_SID,
        Trustee::PrimaryGroup => GROUP_FALLBACK,
        Trustee::User(s) | Trustee::Group(s) => s,
    }
}

/// `group@` is rewritten to the primary group before building, so this
/// constant is never emitted in practice; it exists to keep `ace_sid`
/// total. See `reify_group`.
const GROUP_FALLBACK: &str = EVERYONE_SID;

/// Replaces `group@` trustees with the object's primary group SID, the
/// write-side counterpart of the recognition done on read.
pub fn reify_group(aces: &mut [Ace], primary_group: &str) {
    for a in aces {
        if matches!(a.trustee, Trustee::PrimaryGroup) && !primary_group.is_empty() {
            a.trustee = Trustee::Group(primary_group.to_string());
        }
    }
}

/// Writes the DACL. Only the DACL is passed — sending owner/SACL here is
/// how icacls once ended up clearing them.
pub fn write_dacl(path: &str, follow: bool, acl: &[u8]) -> Result<(), String> {
    let dacl = acl.as_ptr() as *const ACL;
    let rc = if follow {
        let w = to_wide(&win_path(path));
        unsafe {
            SetNamedSecurityInfoW(
                w.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                dacl,
                std::ptr::null(),
            )
        }
    } else {
        // WRITE_DAC to modify, READ_CONTROL is implied by ownership of the
        // handle; request both to be safe.
        let handle = open_handle(path, 0x0004_0000 | 0x0002_0000)?;
        let rc = unsafe {
            SetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                dacl,
                std::ptr::null(),
            )
        };
        unsafe { CloseHandle(handle) };
        rc
    };
    if rc != 0 {
        return Err(WinErr(rc as u32).to_string());
    }
    Ok(())
}

/// Owner of a process, as `DOMAIN\name`. Takes an already-open process
/// handle (the caller keeps ownership of closing it).
pub fn process_owner(process: HANDLE) -> Option<String> {
    use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY};
    use windows_sys::Win32::System::Threading::OpenProcessToken;

    let mut token: HANDLE = std::ptr::null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return None;
    }
    let out = (|| {
        let mut needed = 0u32;
        unsafe {
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed)
        };
        if needed == 0 {
            return None;
        }
        let mut buf = vec![0u8; needed as usize];
        if unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buf.as_mut_ptr() as *mut core::ffi::c_void,
                needed,
                &mut needed,
            )
        } == 0
        {
            return None;
        }
        // TOKEN_USER { User: SID_AND_ATTRIBUTES { Sid: PSID, Attributes } }
        // — the SID pointer is the first pointer-size field of the buffer.
        let sid: PSID = unsafe { *(buf.as_ptr() as *const PSID) };
        let sid = sid_to_string(sid)?;
        Some(lookup_sid(&sid).0)
    })();
    unsafe { CloseHandle(token) };
    out
}
