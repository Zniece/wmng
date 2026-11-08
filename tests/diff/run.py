#!/usr/bin/env python3
"""Differential test: wmng getfacl vs PowerShell Get-Acl.

The unit tests verify the model against my reading of FreeBSD; this harness
verifies the rendered DACL against what Windows itself reports through
Get-Acl - a different oracle making a different claim.

Comparison is semantic, not textual: each ACE becomes the tuple
(sid, type, mask, inherited) on both sides. Account-name spelling and entry
order are not compared (Get-Acl lists the stored order and names; our
rendering is the same order but SIDs and compact letters).

Run from the wmng root (WSL side):  python3 tests/diff/run.py
"""

import os
import subprocess
import sys
import tempfile

# Absolute paths everywhere: the harness may be invoked from any CWD, and
# cmd.exe spawned from python does not inherit this directory.
def wpath(p):
    """Linux-side /mnt/c path -> C:\\ path for the Windows tools."""
    assert p.startswith("/mnt/") and len(p) > 6
    return p[5].upper() + ":\\" + p[7:].replace("/", "\\")


ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WMNG_LINUX = os.path.join(ROOT, "target", "debug", "wmng.exe")
if not os.path.exists(WMNG_LINUX):
    sys.exit("build first: cargo build")
WMNG = wpath(WMNG_LINUX)

# Compact letters -> access bits, same order as the model's PERM_TABLE.
PERM_BITS = {
    'r': 0x000001, 'w': 0x000002, 'x': 0x000020, 'p': 0x000004,
    'D': 0x000040, 'd': 0x010000, 'a': 0x000080, 'A': 0x000100,
    'R': 0x000008, 'W': 0x000010, 'c': 0x020000, 'C': 0x040000,
    'o': 0x080000, 's': 0x100000,
}
FLAG_BITS = {'f': 0x1, 'd': 0x2, 'i': 0x8, 'n': 0x4, 'S': 0x40, 'F': 0x80, 'I': 0x10}


def wpath(p):
    """Linux-side /mnt/c path -> C:\\ path for the Windows tools."""
    assert p.startswith("/mnt/") and len(p) > 6
    return p[5].upper() + ":\\" + p[7:].replace("/", "\\")


def cmd(args, cwd=None, check=True):
    r = subprocess.run(args, capture_output=True, text=True, cwd=cwd)
    if check and r.returncode != 0:
        sys.exit(f"command failed: {args}\n{r.stdout}\n{r.stderr}")
    return r


def winrun(exe, args):
    """Runs a Windows binary from WSL, CRLF-stripped; returns (merged, rc)."""
    r = subprocess.run(["cmd.exe", "/c", exe, *args], capture_output=True, text=True, errors="replace")
    out = r.stdout.replace("\r\n", "\n") + r.stderr.replace("\r\n", "\n")
    return out, r.returncode


def wmng_entries(path, primary_group_sid):
    """Parses `getfacl -n -q` output into (sid, type, mask, inherited)."""
    out, rc = winrun(WMNG, ["getfacl", "-n", "-q", path])
    if rc != 0:
        sys.exit(f"getfacl failed on {path}:\n{out}")
    entries = []
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # who itself may contain ':' ("user:S-1-..."), so split
        # from the right: perms, flags, type are single-colon fields.
        who, perms, flags, etype = line.rsplit(':', 3)
        mask = sum(PERM_BITS[c] for c in perms if c in PERM_BITS)
        inherited = 1 if 'I' in flags else 0
        if who == 'owner@':
            sid = 'S-1-3-4'
        elif who == 'everyone@':
            sid = 'S-1-1-0'
        elif who == 'group@':
            sid = primary_group_sid
        elif who.startswith('user:'):
            sid = who[5:]
        elif who.startswith('group:'):
            sid = who[6:]
        else:
            sys.exit(f"unparseable who field: {who!r}")
        entries.append((sid, etype, mask, inherited))
    return sorted(entries)


PS_TEMPLATE = r"""
$acl = Get-Acl -LiteralPath '{path}'
$group = $acl.Group.Translate([System.Security.Principal.SecurityIdentifier]).Value
Write-Output "GROUP`t$group"
foreach ($ace in $acl.Access) {{
  $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
  $t = [int]$ace.AccessControlType
  $m = [int64]$ace.FileSystemRights
  $i = [int]$ace.IsInherited
  Write-Output "ACE`t$sid`t$t`t$m`t$i"
}}
"""


def ps_entries(path):
    """Asks PowerShell for the same tuples, plus the primary group SID."""
    r = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", PS_TEMPLATE.format(path=path)],
        capture_output=True, text=True, errors="replace")
    if r.returncode != 0:
        sys.exit(f"Get-Acl failed on {path}:\n{r.stdout}\n{r.stderr}")
    group = None
    entries = []
    for line in r.stdout.replace("\r\n", "\n").splitlines():
        parts = line.split('\t')
        if parts[0] == 'GROUP':
            group = parts[1]
        elif parts[0] == 'ACE':
            # .NET AccessControlType: 0 = Allow, 1 = Deny.
            entries.append((parts[1], 'allow' if parts[2] == '0' else 'deny',
                           int(parts[3]), int(parts[4])))
    return group, sorted(entries)


def wpath(p):
    """Linux-side /mnt/c path -> C:\\ path for the Windows tools."""
    assert p.startswith("/mnt/") and len(p) > 6
    return p[5].upper() + ":\\" + p[7:].replace("/", "\\")


def main():
    scratch = tempfile.mkdtemp(prefix="wmng-diff-", dir=os.path.abspath("."))
    cases = []

    def make(name):
        linux = os.path.join(scratch, name)
        with open(linux, "w") as fh:
            fh.write("x\n")
        return wpath(linux)

    # 1. fresh file - purely inherited.
    cases.append(("inherited only", make("f_inherit.txt")))

    # 2. protected file - all explicit copies.
    f = make("f_protect.txt")
    winrun("icacls.exe", [f, "/inheritance:d"])
    cases.append(("protected, explicit copies", f))

    # 3. our own writes: a deny and an everyone@ allow.
    f = make("f_set.txt")
    out, rc = winrun(WMNG, ["setfacl", "-m", "everyone@:rx:allow,everyone@:w:deny", f])
    if rc != 0:
        sys.exit(f"setfacl failed:\n{out}")
    cases.append(("written by setfacl", f))

    failures = 0
    for label, f in cases:
        group, ps = ps_entries(f)
        ours = wmng_entries(f, group)
        if ps == ours:
            print(f"PASS  {label}: {len(ours)} entries match")
        else:
            failures += 1
            print(f"FAIL  {label}")
            print("  Get-Acl:", ps)
            print("  wmng   :", ours)

    print()
    print("differential:", "all match" if failures == 0 else f"{failures} FAILED")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
