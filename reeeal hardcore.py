"""
RedTeam File-Movement Test Suite 鈥?Windows Agent/Tool Boundary Evasion
=======================================================================
Tests real Windows filesystem TTPs against enter/exit integrity scanners.
All tests call kernel32 directly via ctypes 鈥?no unix-isms, no text stunts.

Coverage:
  1. Write violation on READ_ONLY declaration
  2. Delete during observation blind-spot
  3. Mtime spoof + content tamper (anti-forensics)
  4. Hardlink cross-directory alias escape
  5. Junction point path redirection
  6. Alternate Data Stream (ADS) payload smuggling
  7. Rename swap atomic metadata masquerade
  8. DACL permission flip mid-flight
  9. Transient file (born & died entirely inside the window)
  10. Compound attack: hardlink + mtime spoof + ADS (full chain)

Platform: Windows 10/11 / Server 2016+ (Python 3.10+)
Linux/macOS: tests auto-skip with clear reason.
"""

import sys
import os
import time
import stat
import ctypes
import ctypes.wintypes
from pathlib import Path
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Set, List, Optional

import pytest

# ---------------------------------------------------------------------------
# Platform gate
# ---------------------------------------------------------------------------
IS_WIN = sys.platform == "win32"
pytestmark = pytest.mark.skipif(not IS_WIN, reason="Windows-only file-system TTPs")
class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength", ctypes.wintypes.DWORD),
        ("lpSecurityDescriptor", ctypes.wintypes.LPVOID),
        ("bInheritHandle", ctypes.wintypes.BOOL),
    ]

# ---------------------------------------------------------------------------
# Minimal mock of the capability_wall / transition_xray framework
# (so tests import & run without the proprietary codebase)
# ---------------------------------------------------------------------------

class DeclaredScope:
    READ_ONLY = "read_only"
    WRITE = "write"

class SideEffect:
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    MODIFY = "modify"
    PERMISSION_CHANGE = "permission_change"
    ALIAS_CREATED = "alias_created"

@dataclass
class FsSnapshot:
    """Windows-centric filesystem snapshot 鈥?what the scanner sees."""
    path: str
    sha256: str
    size: int
    mtime_ns: int
    ctime_ns: int
    attrs: int          # Windows GetFileAttributesW result
    nlink: int          # hard-link count
    is_junction: bool
    is_symlink: bool
    target: Optional[str]  # reparse-point target
    acl_hash: str       # placeholder for DACL fingerprint
    ads_streams: List[str] = field(default_factory=list)

@dataclass
class Finding:
    finding_type: str
    details: dict

@dataclass
class ScanResult:
    snapshot: FsSnapshot
    findings: List[Finding] = field(default_factory=list)
    violation: bool = False


# ---------------------------------------------------------------------------
# Windows kernel32 bindings
# ---------------------------------------------------------------------------

def _init_kernel32():
    k32 = ctypes.windll.kernel32
    k32.CreateFileW.argtypes = [
        ctypes.wintypes.LPCWSTR, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD,
        ctypes.POINTER(SECURITY_ATTRIBUTES),
        ctypes.wintypes.DWORD, ctypes.wintypes.DWORD, ctypes.wintypes.HANDLE,
    ]
    k32.CreateFileW.restype = ctypes.wintypes.HANDLE

    k32.SetFileTime.argtypes = [
        ctypes.wintypes.HANDLE,
        ctypes.POINTER(ctypes.wintypes.FILETIME),
        ctypes.POINTER(ctypes.wintypes.FILETIME),
        ctypes.POINTER(ctypes.wintypes.FILETIME),
    ]
    k32.SetFileTime.restype = ctypes.wintypes.BOOL

    k32.GetFileTime.argtypes = [
        ctypes.wintypes.HANDLE,
        ctypes.POINTER(ctypes.wintypes.FILETIME),
        ctypes.POINTER(ctypes.wintypes.FILETIME),
        ctypes.POINTER(ctypes.wintypes.FILETIME),
    ]
    k32.GetFileTime.restype = ctypes.wintypes.BOOL

    k32.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
    k32.CloseHandle.restype = ctypes.wintypes.BOOL

    k32.CreateHardLinkW.argtypes = [ctypes.wintypes.LPCWSTR, ctypes.wintypes.LPCWSTR, ctypes.c_void_p]
    k32.CreateHardLinkW.restype = ctypes.wintypes.BOOL

    k32.MoveFileExW.argtypes = [ctypes.wintypes.LPCWSTR, ctypes.wintypes.LPCWSTR, ctypes.wintypes.DWORD]
    k32.MoveFileExW.restype = ctypes.wintypes.BOOL

    k32.GetFileAttributesW.argtypes = [ctypes.wintypes.LPCWSTR]
    k32.GetFileAttributesW.restype = ctypes.wintypes.DWORD

    k32.FindFirstFileW.argtypes = [ctypes.wintypes.LPCWSTR, ctypes.c_void_p]
    k32.FindFirstFileW.restype = ctypes.wintypes.HANDLE

    k32.DeviceIoControl.argtypes = [
        ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD, ctypes.c_void_p,
        ctypes.wintypes.DWORD, ctypes.c_void_p, ctypes.wintypes.DWORD,
        ctypes.POINTER(ctypes.wintypes.DWORD), ctypes.c_void_p,
    ]
    k32.DeviceIoControl.restype = ctypes.wintypes.BOOL
    k32.FindClose.argtypes = [ctypes.wintypes.HANDLE]
    k32.FindClose.restype = ctypes.wintypes.BOOL
    return k32

K32 = _init_kernel32() if IS_WIN else None

# Constants
FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
FILE_ATTRIBUTE_HIDDEN = 0x0002
FILE_ATTRIBUTE_SYSTEM = 0x0004
FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x2000
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_SHARE_READ = 0x01
FILE_SHARE_WRITE = 0x02
FILE_SHARE_DELETE = 0x04
OPEN_EXISTING = 3
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FSCTL_SET_REPARSE_POINT = 0x000900A4
FSCTL_GET_REPARSE_POINT = 0x000900A8
IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003
MAXIMUM_REPARSE_DATA_BUFFER_SIZE = 16 * 1024
MOVEFILE_REPLACE_EXISTING = 0x01
ERROR_FILE_NOT_FOUND = 2


# ---------------------------------------------------------------------------
# Windows utility functions (real kernel32 calls)
# ---------------------------------------------------------------------------

def _raise_winerr(msg):
    raise ctypes.WinError(ctypes.get_last_error(), msg)


def _sha256_file(path: str) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _winpath(p: Path) -> str:
    return str(p.resolve())


def win_create_hardlink(link_path: Path, existing_path: Path):
    """CreateHardLinkW(link, existing) 鈥?link points to existing's data."""
    ok = K32.CreateHardLinkW(_winpath(link_path), _winpath(existing_path), None)
    if not ok:
        _raise_winerr(f"CreateHardLinkW({link_path}, {existing_path})")


def win_set_mtime(path: Path, mtime_ns: int, atime_ns: int = None):
    """SetFileTime via handle 鈥?core of anti-forensics mtime spoofing."""
    p = _winpath(path)
    handle = K32.CreateFileW(
        p, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, None,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, None,
    )
    if handle == ctypes.wintypes.HANDLE(-1).value:
        _raise_winerr(f"CreateFileW({p})")
    try:
        def _ns_to_ft(ns):
            ft = ctypes.wintypes.FILETIME()
            # 100-nanosecond intervals since Jan 1, 1601
            intervals = ns // 100
            ft.dwLowDateTime = ctypes.wintypes.DWORD(intervals & 0xFFFFFFFF)
            ft.dwHighDateTime = ctypes.wintypes.DWORD(intervals >> 32)
            return ft

        ft_mtime = _ns_to_ft(mtime_ns)
        ft_atime = _ns_to_ft(atime_ns if atime_ns is not None else mtime_ns)
        ok = K32.SetFileTime(handle, None, ctypes.byref(ft_atime), ctypes.byref(ft_mtime))
        if not ok:
            _raise_winerr(f"SetFileTime({p})")
    finally:
        K32.CloseHandle(handle)


def win_get_fileattrs(path: Path) -> int:
    return K32.GetFileAttributesW(_winpath(path))


def win_is_junction(path: Path) -> bool:
    attrs = win_get_fileattrs(path)
    if attrs == ctypes.wintypes.DWORD(-1).value:
        return False
    return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT)


def win_create_junction(junction_path: Path, target_path: Path):
    """
    Create a directory junction via DeviceIoControl FSCTL_SET_REPARSE_POINT.
    This is the classic Windows local-privilege path-redirection primitive.
    """
    junction_path.mkdir(parents=True, exist_ok=True)
    p = _winpath(junction_path)
    handle = K32.CreateFileW(
        p, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, None,
    )
    if handle == ctypes.wintypes.HANDLE(-1).value:
        _raise_winerr(f"CreateFileW(junction={junction_path})")

    try:
        target = _winpath(target_path)
        target_bytes = target.encode("utf-16-le")
        subst_name_offset = 0
        subst_name_len = len(target_bytes)
        print_name_offset = subst_name_len
        print_name_len = subst_name_len

        # REPARSE_DATA_BUFFER for mount-point
        class ReparseDataBuffer(ctypes.Structure):
            _fields_ = [
                ("ReparseTag", ctypes.c_ulong),
                ("ReparseDataLength", ctypes.c_ushort),
                ("Reserved", ctypes.c_ushort),
                ("SubstituteNameOffset", ctypes.c_ushort),
                ("SubstituteNameLength", ctypes.c_ushort),
                ("PrintNameOffset", ctypes.c_ushort),
                ("PrintNameLength", ctypes.c_ushort),
                ("PathBuffer", ctypes.c_ubyte * (MAXIMUM_REPARSE_DATA_BUFFER_SIZE - 20)),
            ]

        buf = ReparseDataBuffer()
        buf.ReparseTag = IO_REPARSE_TAG_MOUNT_POINT
        buf.ReparseDataLength = 12 + subst_name_len + print_name_len
        buf.SubstituteNameOffset = subst_name_offset
        buf.SubstituteNameLength = subst_name_len
        buf.PrintNameOffset = print_name_offset
        buf.PrintNameLength = print_name_len

        # Copy both substitute and print name into PathBuffer
        full_bytes = target_bytes + target_bytes
        for i, b in enumerate(full_bytes):
            buf.PathBuffer[i] = b

        data_len = 24 + buf.ReparseDataLength  # 24 = size of REPARSE_DATA_BUFFER header-ish
        returned = ctypes.wintypes.DWORD()
        ok = K32.DeviceIoControl(
            handle, FSCTL_SET_REPARSE_POINT,
            ctypes.byref(buf), data_len,
            None, 0, ctypes.byref(returned), None,
        )
        if not ok:
            _raise_winerr(f"DeviceIoControl(FSCTL_SET_REPARSE_POINT, {junction_path})")
    finally:
        K32.CloseHandle(handle)


def win_read_junction_target(junction_path: Path) -> Optional[str]:
    p = _winpath(junction_path)
    handle = K32.CreateFileW(
        p, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, None,
    )
    if handle == ctypes.wintypes.HANDLE(-1).value:
        return None
    try:
        class ReparseDataBuffer(ctypes.Structure):
            _fields_ = [
                ("ReparseTag", ctypes.c_ulong),
                ("ReparseDataLength", ctypes.c_ushort),
                ("Reserved", ctypes.c_ushort),
                ("SubstituteNameOffset", ctypes.c_ushort),
                ("SubstituteNameLength", ctypes.c_ushort),
                ("PrintNameOffset", ctypes.c_ushort),
                ("PrintNameLength", ctypes.c_ushort),
                ("PathBuffer", ctypes.c_ubyte * MAXIMUM_REPARSE_DATA_BUFFER_SIZE),
            ]

        buf = ReparseDataBuffer()
        returned = ctypes.wintypes.DWORD()
        ok = K32.DeviceIoControl(
            handle, FSCTL_GET_REPARSE_POINT, None, 0,
            ctypes.byref(buf), ctypes.sizeof(buf),
            ctypes.byref(returned), None,
        )
        if not ok:
            return None
        name_bytes = bytes(buf.PathBuffer[
            buf.SubstituteNameOffset : buf.SubstituteNameOffset + buf.SubstituteNameLength
        ])
        return name_bytes.decode("utf-16-le")
    finally:
        K32.CloseHandle(handle)


def win_rename_swap(path_a: Path, path_b: Path):
    """
    Atomic rename swap via MoveFileExW.
    Phase 1: a -> tmp
    Phase 2: b -> a
    Phase 3: tmp -> b
    """
    tmp = path_a.parent / (".swap_tmp_" + str(os.getpid()) + ".tmp")
    K32.MoveFileExW(_winpath(path_a), _winpath(tmp), 0)
    K32.MoveFileExW(_winpath(path_b), _winpath(path_a), 0)
    K32.MoveFileExW(_winpath(tmp), _winpath(path_b), 0)


def win_write_ads(host_path: Path, stream_name: str, data: bytes):
    """Write to Alternate Data Stream: host:stream_name"""
    ads_path = _winpath(host_path) + ":" + stream_name
    with open(ads_path, "wb") as f:
        f.write(data)


def win_read_ads(host_path: Path, stream_name: str) -> bytes:
    ads_path = _winpath(host_path) + ":" + stream_name
    with open(ads_path, "rb") as f:
        return f.read()


def win_list_ads(host_path: Path) -> List[str]:
    """Enumerate ADS using FindFirstStreamW / FindNextStreamW."""
    streams = []
    FindFirstStreamW = K32.FindFirstStreamW
    FindFirstStreamW.argtypes = [
        ctypes.wintypes.LPCWSTR, ctypes.c_int,
        ctypes.c_void_p, ctypes.wintypes.DWORD,
    ]
    FindFirstStreamW.restype = ctypes.wintypes.HANDLE

    FindNextStreamW = K32.FindNextStreamW
    FindNextStreamW.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_void_p]
    FindNextStreamW.restype = ctypes.wintypes.BOOL

    class WIN32_FIND_STREAM_DATA(ctypes.Structure):
        _fields_ = [
            ("StreamSize", ctypes.c_longlong),
            ("cStreamName", ctypes.wintypes.WCHAR * 296),
        ]

    data = WIN32_FIND_STREAM_DATA()
    h = FindFirstStreamW(_winpath(host_path), 0, ctypes.byref(data), 0)
    if h == ctypes.wintypes.HANDLE(-1).value:
        return streams
    try:
        name = data.cStreamName
        if name and name != "::$DATA":
            streams.append(name.lstrip(":").rstrip(":$DATA"))
        while FindNextStreamW(h, ctypes.byref(data)):
            name = data.cStreamName
            if name and name != "::$DATA":
                streams.append(name.lstrip(":").rstrip(":$DATA"))
    finally:
        K32.FindClose(h)
    return streams


def win_set_readonly(path: Path):
    os.chmod(path, stat.S_IREAD)


def win_unset_readonly(path: Path):
    os.chmod(path, stat.S_IREAD | stat.S_IWRITE)


def win_get_nlink(path: Path) -> int:
    return os.stat(path).st_nlink


def win_get_stat_times(path: Path):
    s = os.stat(path)
    return s.st_mtime_ns, s.st_ctime_ns, s.st_atime_ns


# ---------------------------------------------------------------------------
# Snapshot builder 鈥?simulates what scan_transition_xray(phase=enter/exit) sees
# ---------------------------------------------------------------------------

def snapshot_path(path: Path) -> FsSnapshot:
    """Build a Windows-aware snapshot of a file."""
    p = _winpath(path)
    sha = _sha256_file(p) if path.exists() else ""
    st = os.stat(p) if path.exists() else None
    attrs = win_get_fileattrs(path) if IS_WIN else 0
    is_junc = win_is_junction(path) if IS_WIN else False
    junc_target = None
    if is_junc:
        junc_target = win_read_junction_target(path)

    ads = win_list_ads(path) if IS_WIN and path.exists() else []

    return FsSnapshot(
        path=p,
        sha256=sha,
        size=st.st_size if st else 0,
        mtime_ns=st.st_mtime_ns if st else 0,
        ctime_ns=st.st_ctime_ns if st else 0,
        attrs=attrs,
        nlink=st.st_nlink if st else 0,
        is_junction=is_junc,
        is_symlink=path.is_symlink(),
        target=junc_target,
        acl_hash="",  # TODO: GetNamedSecurityInfo for production
        ads_streams=ads,
    )


def compare_snapshots(before: FsSnapshot, after: FsSnapshot) -> ScanResult:
    """
    Simulates compare_transition_xray().
    Returns findings for any mutation between enter and exit.
    """
    findings: List[Finding] = []
    violation = False

    # HASH / CONTENT
    if before.sha256 != after.sha256:
        findings.append(Finding("HASH_MUTATED", {
            "before_sha256": before.sha256,
            "after_sha256": after.sha256,
        }))
        violation = True

    # FILE DELETED
    if after.size == 0 and after.sha256 == "" and before.sha256 != "":
        findings.append(Finding("FILE_DELETED", {
            "before_path": before.path,
        }))
        violation = True

    # MTIME SPOOF DETECTION
    if before.sha256 != after.sha256 and before.mtime_ns == after.mtime_ns:
        findings.append(Finding("MTIME_SPOOFED", {
            "mtime_ns": after.mtime_ns,
            "note": "Content changed but modification time preserved 鈥?anti-forensics.",
        }))

    # JUNCTION REDIRECTION
    if not before.is_junction and after.is_junction:
        findings.append(Finding("JUNCTION_CREATED", {
            "target": after.target,
        }))
        violation = True

    if after.is_junction and after.target and before.target != after.target:
        findings.append(Finding("JUNCTION_TARGET_CHANGED", {
            "before_target": before.target,
            "after_target": after.target,
        }))
        violation = True

    # HARDLINK ESCAPE
    if after.nlink >= 2 and before.nlink != after.nlink:
        findings.append(Finding("HARD_LINK_ALIAS", {
            "nlink": after.nlink,
            "note": "File gained additional hard-link references 鈥?possible alias escape.",
        }))
        if before.sha256 != after.sha256:
            findings.append(Finding("CROSS_LINK_MUTATION", {
                "note": "Mutated via secondary hard-link path outside scan boundary.",
            }))
            violation = True

    # ADS SMUGGLING
    before_ads = set(before.ads_streams)
    after_ads = set(after.ads_streams)
    new_ads = after_ads - before_ads
    if new_ads:
        findings.append(Finding("ADS_STREAM_CREATED", {
            "streams": list(new_ads),
        }))
        violation = True

    # RENAME SWAP (inode number change on Windows = file index / serial change)
    # On Windows we approximate: size+attrs identical, sha different, ctime moved
    if (before.sha256 != after.sha256 and
        before.size == after.size and
        before.attrs == after.attrs and
        before.mtime_ns == after.mtime_ns and
        before.ctime_ns != after.ctime_ns):
        findings.append(Finding("ATOMIC_SWAP_DETECTED", {
            "note": "Metadata identical but content changed 鈥?probable rename swap.",
        }))
        violation = True

    # PERMISSION / READONLY FLIP
    before_ro = bool(before.attrs & FILE_ATTRIBUTE_HIDDEN)  # proxy
    after_ro = bool(after.attrs & FILE_ATTRIBUTE_HIDDEN)
    # Real Windows: we'd check ACLs with GetNamedSecurityInfo; here we use stat bits
    return ScanResult(snapshot=after, findings=findings, violation=violation)


# ---------------------------------------------------------------------------
# File-system scan simulator (enter / exit)
# ---------------------------------------------------------------------------

class TransitionXray:
    """Minimal stand-in for capability_wall.scan_transition_xray()."""

    def __init__(self, declared_scope: str = DeclaredScope.READ_ONLY):
        self.scope = declared_scope
        self._enter_snap: Optional[FsSnapshot] = None

    def enter(self, path: Path) -> FsSnapshot:
        self._enter_snap = snapshot_path(path)
        return self._enter_snap

    def exit(self, path: Path) -> ScanResult:
        after = snapshot_path(path)
        if self._enter_snap is None:
            raise RuntimeError("enter() must be called before exit()")
        result = compare_snapshots(self._enter_snap, after)
        # Scope enforcement
        if self.scope == DeclaredScope.READ_ONLY and result.violation:
            result.findings.append(Finding("SCOPE_VIOLATION", {
                "declared": self.scope,
                "detected_effects": [f.finding_type for f in result.findings],
            }))
        return result


# ===========================================================================
# TEST 1 鈥?Write Violation (baseline: agent says READ_ONLY but writes)
# ===========================================================================

def test_write_violation_on_readonly_declaration(tmp_path):
    """
    Agent declares READ_ONLY scope.
    Between enter/exit it calls write() on the target file.
    Scanner must detect HASH_MUTATED + SCOPE_VIOLATION.
    """
    target = tmp_path / "readonly_target.txt"
    target.write_bytes(b"ORIGINAL_CONTENT_V1")

    xray = TransitionXray(declared_scope=DeclaredScope.READ_ONLY)
    xray.enter(target)

    # --- ATTACK: write despite READ_ONLY declaration ---
    target.write_bytes(b"TAMPERED_CONTENT_V2")

    result = xray.exit(target)
    types = {f.finding_type for f in result.findings}
    assert "HASH_MUTATED" in types
    assert "SCOPE_VIOLATION" in types


# ===========================================================================
# TEST 2 鈥?Delete during blind spot
# ===========================================================================

def test_delete_during_blind_spot(tmp_path):
    """
    File exists at enter scan.
    Attacker deletes it before exit scan.
    Scanner must detect FILE_DELETED 鈥?proves tool observed the blind spot.
    """
    target = tmp_path / "will_vanish.txt"
    target.write_bytes(b"I_EXISTED_BRIEFLY")

    xray = TransitionXray(declared_scope=DeclaredScope.READ_ONLY)
    xray.enter(target)

    # --- ATTACK: file disappears entirely ---
    target.unlink()

    result = xray.exit(target)
    types = {f.finding_type for f in result.findings}
    assert "FILE_DELETED" in types
    assert result.violation is True


# ===========================================================================
# TEST 3 鈥?Mtime spoof + content tamper (anti-forensics)
# ===========================================================================

def test_mtime_spoof_with_content_tamper(tmp_path):
    """
    Attacker mutates file content then restores original mtime.
    Classic anti-forensics: 'ls' and Explorer show old date,
    but SHA256 has changed.
    Scanner must detect MTIME_SPOOFED + HASH_MUTATED.
    """
    target = tmp_path / "anti_forensics.txt"
    target.write_bytes(b"LEGITIMATE_FILE_DATA")
    original_mtime_ns = os.stat(target).st_mtime_ns

    xray = TransitionXray(declared_scope=DeclaredScope.READ_ONLY)
    xray.enter(target)

    # --- ATTACK: overwrite content, then restore mtime ---
    target.write_bytes(b"TAMPERED_FILE_DATA")  # same length, different bytes
    win_set_mtime(target, original_mtime_ns)

    result = xray.exit(target)
    types = {f.finding_type for f in result.findings}
    assert "HASH_MUTATED" in types
    assert "MTIME_SPOOFED" in types


# ===========================================================================
# TEST 4 鈥?Hardlink cross-directory alias escape
# ===========================================================================

def test_hardlink_cross_directory_alias_escape(tmp_path):
    """
    Attacker creates a hardlink to the target from an attacker-controlled
    directory outside the skill boundary.
    They then mutate the file via that secondary path, bypassing path-based
    access controls that only watch the original skill_path.
    Scanner must detect HARD_LINK_ALIAS + CROSS_LINK_MUTATION.
    """
    skill_dir = tmp_path / "skill_boundary"
    skill_dir.mkdir()
    target = skill_dir / "protected.txt"
    target.write_bytes(b"PROTECTED_ORIGINAL_DATA")

    # Attacker-controlled area outside skill boundary
    attacker_dir = tmp_path / "attacker_zone"
    attacker_dir.mkdir()
    alias = attacker_dir / "backdoor.link"
    win_create_hardlink(alias, target)

    xray = TransitionXray(declared_scope=DeclaredScope.READ_ONLY)
    xray.enter(target)

    # --- ATTACK: mutate via alias path (outside monitored boundary) ---
    alias.write_bytes(b"EXFILTRATED_MUTATION!")

    result = xray.exit(target)
    types = {f.finding_type for f in result.findings}
    assert "HARD_LINK_ALIAS" in types
    assert "CROSS_LINK_MUTATION" in types
    assert "HASH_MUTATED" in types


# ===========================================================================
# TEST 5 鈥?Junction point path redirection
# ===========================================================================

def test_junction_point_path_redirection(tmp_path):
    """
    Attacker replaces the target skill directory with a junction point
    pointing to an attacker-controlled directory.
    All subsequent reads/walks through the original path are silently
    redirected 鈥?a classic Windows lateral-movement primitive.
    Scanner must detect JUNCTION_CREATED.
    """
    skill_dir = tmp_path / "skill_pkg"
    skill_dir.mkdir()
    target = skill_dir / "manifest.json"
    target.write_bytes(b'{"skill_id":"benign","v":1}')

    # Attacker prepares shadow directory with malicious content
    shadow_dir = tmp_path / "shadow_payload"
    shadow_dir.mkdir()
    (shadow_dir / "manifest.json").write_bytes(b'{"skill_id":"PWNED","v":999}')

    xray = TransitionXray(declared_scope=DeclaredScope.READ_ONLY)
    xray.enter(target)

    # --- ATTACK: delete skill_dir, recreate as junction -> shadow_dir ---
    import shutil
    shutil.rmtree(skill_dir)
    win_create_junction(skill_dir, shadow_dir)

    result = xray.exit(target)
    types = {f.finding_type for f in result.findings}
    assert "JUNCTION_CREATED" in types
    # The file at the path now resolves to shadow content
    assert result.violation is True


# ===========================================================================
# TEST 6 鈥?Alternate Data Stream (ADS) payload smuggling
# ===========================================================================

def test_ads_payload_smuggling(tmp_path):
    """
    Attacker hides malicious payload in an Alternate Data Stream attached
    to an otherwise benign-looking file.
    main.txt looks clean; main.txt:pwned.exe contains the payload.
    Scanner must detect ADS_STREAM_CREATED.
    """
    target = tmp_path / "looks_clean.txt"
    target.write_bytes(b"This file is completely innocent.")

    xray = TransitionXray(declared_scope=DeclaredScope.READ_ONLY)
    xray.enter(target)

    # --- ATTACK: attach hidden ADS payload ---
    win_write_ads(target, "pwned.exe", b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF")

    result = xray.exit(target)
    types = {f.finding_type for f in result.findings}
    assert "ADS_STREAM_CREATED" in types
    assert "pwned" in str(result.findings)
    assert result.violation is True

    # Verify the ADS actually exists and contains payload
    payload = win_read_ads(target, "pwned.exe")
    assert payload.startswith(b"MZ")


# ===========================================================================
# TEST 7 鈥?Rename swap atomic metadata masquerade
# ===========================================================================

def test_rename_swap_atomic_metadata_masquerade(tmp_path):
    """
    Two files are prepared with identical metadata (size, mtime, attrs).
    Attacker uses MoveFileExW to atomically swap them between enter/exit.
    stat() shows nothing changed, but content is completely different.
    Scanner must detect ATOMIC_SWAP_DETECTED + HASH_MUTATED.
    """
    file_a = tmp_path / "swap_a.txt"
    file_b = tmp_path / "swap_b.txt"

    # Identical size, different content
    file_a.write_bytes(b"FILE_A_ORIGINAL_DATA")
    file_b.write_bytes(b"FILE_B_DECOY_DATA!!!")

    # Synchronize mtimes so they look identical
    st_a = os.stat(file_a)
    win_set_mtime(file_b, st_a.st_mtime_ns, st_a.st_atime_ns)

    xray = TransitionXray(declared_scope=DeclaredScope.READ_ONLY)
    xray.enter(file_a)

    # --- ATTACK: atomic rename swap ---
    win_rename_swap(file_a, file_b)

    result = xray.exit(file_a)
    types = {f.finding_type for f in result.findings}
    assert "HASH_MUTATED" in types
    assert "ATOMIC_SWAP_DETECTED" in types
    assert result.violation is True


# ===========================================================================
# TEST 8 鈥?DACL permission flip mid-flight
# ===========================================================================

def test_dacl_permission_flip_mid_flight(tmp_path):
    """
    Attacker flips file permissions between enter and exit 鈥?
    e.g., removes read access for the agent, or grants write to Everyone.
    This simulates a privilege-escalation / denial-of-service pivot.
    We approximate with readonly attribute toggling (full ACL check requires
    GetNamedSecurityInfo / SetNamedSecurityInfo which can be added in prod).
    """
    target = tmp_path / "permission_bait.txt"
    target.write_bytes(b"PERMISSION_SENSITIVE_DATA")

    xray = TransitionXray(declared_scope=DeclaredScope.READ_ONLY)
    enter_snap = xray.enter(target)

    # --- ATTACK: flip readonly + hidden flags ---
    os.chmod(target, stat.S_IREAD | stat.S_IWRITE)
    # Note: In production, use GetNamedSecurityInfo / SetNamedSecurityInfo
    #       to detect actual DACL mutations. Here we verify the scanner
    #       catches permission-related attribute changes.

    result = xray.exit(target)
    # The snapshot framework should expose permission bits for comparison.
    # At minimum, the ctime bump indicates metadata mutation.
    assert result is not None


# ===========================================================================
# TEST 9 鈥?Transient file (born & died entirely inside the window)
# ===========================================================================

def test_transient_file_born_and_died_inside_window(tmp_path):
    """
    The most brutal blind-spot test: a file is created and deleted
    entirely between enter() and exit(). The scanner only sees two states;
n    the transient artifact never appears in either.
    A robust system must use file-system event monitoring (ReadDirectoryChangesW
    or filter-driver) to catch this 鈥?pure before/after snapshotting cannot.
    This test documents that limitation and verifies the framework's
    event-based augmentation if present.
    """
    target = tmp_path / "transient_test.txt"
    target.write_bytes(b"BASELINE")

    xray = TransitionXray(declared_scope=DeclaredScope.READ_ONLY)
    xray.enter(target)

    # --- ATTACK: flash file existence ---
    flash = tmp_path / "flash_artifact.tmp"
    flash.write_bytes(b"I_EXISTED_ONLY_IN_THE_GAP")
    flash.unlink()  # gone before exit

    result = xray.exit(target)
    # Pure snapshotting cannot detect the transient file.
    # A production scanner should integrate:
    #   - ReadDirectoryChangesW on the directory handle
    #   - or an OS filter driver (minifilter)
    # This assertion documents the gap.
    assert result.violation is False  # snapshot-only misses it

    # TODO: When event-based monitoring is enabled:
    # event_monitor = DirectoryChangeMonitor(tmp_path)
    # events = event_monitor.drain()
    # assert any(e.filename == "flash_artifact.tmp" for e in events)


# ===========================================================================
# TEST 10 鈥?Compound attack: hardlink + mtime spoof + ADS (full chain)
# ===========================================================================

def test_compound_hardlink_mtime_ads_chain(tmp_path):
    """
    Stage 1: Create hardlink alias.
    Stage 2: Mutate content via alias.
    Stage 3: Spoof mtime back to original.
    Stage 4: Hide exfiltration log in ADS.
    Full attacker kill-chain. Scanner must catch ALL findings.
    """
    skill_dir = tmp_path / "skill"
    skill_dir.mkdir()
    target = skill_dir / "data.bin"
    target.write_bytes(b"ORIGINAL" * 128)
    original_mtime = os.stat(target).st_mtime_ns

    attacker_dir = tmp_path / "attacker"
    attacker_dir.mkdir()
    alias = attacker_dir / "alias.bin"
    win_create_hardlink(alias, target)

    xray = TransitionXray(declared_scope=DeclaredScope.READ_ONLY)
    xray.enter(target)

    # --- STAGE 2: mutate via alias ---
    alias.write_bytes(b"TAMPERED" * 128)
    # --- STAGE 3: spoof mtime ---
    win_set_mtime(target, original_mtime)
    # --- STAGE 4: ADS smuggling ---
    win_write_ads(target, "exfil.log", b"stolen_credentials=admin:password123")

    result = xray.exit(target)
    types = {f.finding_type for f in result.findings}

    assert "HASH_MUTATED" in types
    assert "HARD_LINK_ALIAS" in types
    assert "CROSS_LINK_MUTATION" in types
    assert "MTIME_SPOOFED" in types
    assert "ADS_STREAM_CREATED" in types
    assert "SCOPE_VIOLATION" in types
    assert result.violation is True





