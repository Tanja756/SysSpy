import hashlib
import ipaddress
import os

import psutil


def is_local_ip(ip):
    """True for RFC1918 / loopback / link-local / multicast / reserved addresses."""
    if not ip:
        return True
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (
        a.is_private
        or a.is_loopback
        or a.is_link_local
        or a.is_multicast
        or a.is_reserved
        or a.is_unspecified
    )


def exe_of_pid(pid):
    if not pid:
        return None
    try:
        return psutil.Process(pid).exe()
    except Exception:
        return None


def proc_context(pid):
    """Краткая контекстная строка о процессе: cmdline, cwd, пользователь.

    Помогает понять, что именно запустил процесс и откуда (рабочая директория),
    что критично для находок сети — одного имени бинарника (python3) недостаточно.
    """
    if not pid:
        return ""
    try:
        p = psutil.Process(pid)
        try:
            cmd = " ".join(p.cmdline()) or p.name()
        except Exception:
            cmd = p.name() if hasattr(p, "name") else "?"
        try:
            cwd = p.cwd()
        except Exception:
            cwd = None
        try:
            user = p.username()
        except Exception:
            user = None
    except Exception:
        return ""
    parts = [f"cmd={cmd[:200]}"]
    if cwd:
        parts.append(f"cwd={cwd}")
    if user:
        parts.append(f"user={user}")
    return " ".join(parts)


def file_sha256(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def iter_proc_pids():
    try:
        return [int(p) for p in os.listdir("/proc") if p.isdigit()]
    except Exception:
        return []
