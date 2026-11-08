//! Win32 bindings, one module per domain. This directory is the ONLY place
//! in wmng that may call Windows; everything above it is portable model
//! code testable on any OS.

use windows_sys::Win32::Foundation::GetLastError;

pub mod power;
pub mod security;

// The applet-facing surface: names stay `providers::read_sd` etc., so the
// applet layer does not care which provider module a call lives in.
pub use security::{build_acl, lookup_name, lookup_sid, read_sd, reify_group, write_dacl};
pub fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub fn from_wide(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

/// Normalises a path for the wide APIs. Forward slashes become
/// backslashes; `\\?\` is added to absolute paths so paths longer than
/// 260 characters work. A relative path is returned unchanged: `\\?\`
/// accepts absolute paths ONLY, and silently prefixing one turns a working
/// relative path into "path not found".
pub fn win_path(path: &str) -> String {
    let p = path.replace('/', "\\");
    if p.starts_with(r"\\?\") || p.starts_with(r"\\.\") {
        return p;
    }
    let drive_absolute = p.len() >= 3
        && p.as_bytes()[1] == b':'
        && p.as_bytes()[0].is_ascii_alphabetic()
        && (p.as_bytes()[2] == b'\\' || p.as_bytes()[2] == b'/');
    if p.starts_with(r"\\") {
        // UNC path: \\?\UNC\\server\\share
        format!(r"\\?\UNC\{}", &p[2..])
    } else if drive_absolute {
        format!(r"\\?\{p}")
    } else {
        p
    }
}



/// Win32 error code; the applet formats the message.
#[derive(Debug)]
pub struct WinErr(pub u32);

pub fn last_error() -> WinErr {
    WinErr(unsafe { GetLastError() })
}

impl WinErr {
    pub fn to_string(self) -> String {
        let n = self.0;
        match n {
            2 => "no such file or directory".into(),
            3 => "no such directory".into(),
            5 => "access denied (run elevated?)".into(),
            87 => "invalid parameter".into(),
            1314 => "privilege not held; run elevated".into(),
            // 1115/1116/1190 read differently depending on whether a
            // request or an abort failed; the callers re-word them.
            1115 | 1116 | 1190 => "shutdown state error".into(),
            1223 => "cancelled".into(),
            _ => format!("windows error {n}"),
        }
    }
}


#[cfg(test)]
mod tests {
    use super::win_path;

    #[test]
    fn relative_paths_stay_relative() {
        // \\?\ accepts absolute paths only; prefixing a relative path
        // turns it into "path not found". This bit us once in -R mode.
        assert_eq!(win_path("f.txt"), "f.txt");
        assert_eq!(win_path("sub"), "sub");
        assert_eq!(win_path(r"sub\deep\h.txt"), r"sub\deep\h.txt");
        assert_eq!(win_path("sub/g.txt"), r"sub\g.txt");
    }

    #[test]
    fn absolute_paths_gain_the_prefix() {
        assert_eq!(win_path(r"C:\Users"), r"\\?\C:\Users");
        assert_eq!(win_path("C:/Users/znie"), r"\\?\C:\Users\znie");
        assert_eq!(win_path(r"D:\x"), r"\\?\D:\x");
    }

    #[test]
    fn unc_paths_get_the_unc_form() {
        assert_eq!(win_path(r"\\server\share\file"), r"\\?\UNC\server\share\file");
    }

    #[test]
    fn already_prefixed_paths_are_untouched() {
        assert_eq!(win_path(r"\\?\C:\long"), r"\\?\C:\long");
        assert_eq!(win_path(r"\\.\COM1"), r"\\.\COM1");
    }

    #[test]
    fn drive_like_text_is_not_prefixed() {
        // "C:something" (no separator after the colon) is a drive-relative
        // path, not an absolute one.
        assert_eq!(win_path(r"C:file.txt"), r"C:file.txt");
    }
}
