import os
import re

from ..finding import Finding, Severity
from .. import utils

SUSP_MODULE = re.compile(r"(hide|rootkit|backdoor|keylog|spy|hook)", re.I)

# Процессы, легитимно открывающие /dev/input/event* (X-сервер, композиторы,
# logind, менеджеры входа). Это не кейлоггеры.
INPUT_ALLOW = {
    "Xorg", "X", "Xwayland", "gnome-shell", "mutter", "weston", "wayland",
    "systemd-logind", "gdm", "gdm-x-session", "lightdm", "sddm", "acpid",
    "upowerd", "libinput", "xinit", "gnome-session", "plasmashell",
    "systemd",  # PID 1 в контейнерах/VM может держать fd устройства ввода
}


def _scan_input(state, config):
    out = []
    for pid in utils.iter_proc_pids():
        try:
            fd_dir = f"/proc/{pid}/fd"
            for fd in os.listdir(fd_dir):
                link = os.readlink(os.path.join(fd_dir, fd))
                if link.startswith("/dev/input/event"):
                    try:
                        with open(f"/proc/{pid}/comm") as f:
                            comm = f.read().strip()
                    except Exception:
                        comm = "?"
                    if comm in INPUT_ALLOW:
                        continue
                    out.append(
                        Finding(
                            "ввод",
                            "Процесс читает устройство ввода",
                            f"PID {pid} ({comm}) имеет fd на {link} "
                            f"— возможен кейлоггер / захват экрана",
                            Severity.HIGH,
                        )
                    )
                    break
        except Exception:
            continue
    return out


def _scan_ptrace(state, config):
    out = []
    for pid in utils.iter_proc_pids():
        try:
            with open(f"/proc/{pid}/status") as f:
                txt = f.read()
        except Exception:
            continue
        m = re.search(r"TracerPid:\s*(\d+)", txt)
        if m and int(m.group(1)) != 0:
            tracer = m.group(1)
            try:
                with open(f"/proc/{pid}/comm") as f:
                    comm = f.read().strip()
            except Exception:
                comm = "?"
            out.append(
                Finding(
                    "ввод",
                    "Процесс под отладкой (ptrace)",
                    f"PID {pid} ({comm}) отлаживается процессом PID {tracer}",
                    Severity.WARN,
                )
            )
    return out


def _scan_modules(state, config):
    out = []
    first_run = state.count_modules() == 0
    try:
        with open("/proc/modules") as f:
            mods = [l.split()[0] for l in f if l.strip()]
    except Exception:
        mods = []
    for name in mods:
        known = state.remember_module(name)
        if SUSP_MODULE.search(name):
            out.append(
                Finding(
                    "ввод",
                    "Подозрительное имя модуля ядра",
                    f"модуль {name} совпадает с подозрительным шаблоном",
                    Severity.HIGH,
                )
            )
        elif not known and not first_run and not name.startswith(config.ok_module_prefixes):
            out.append(
                Finding(
                    "ядро",
                    "Новый модуль ядра",
                    f"модуль {name} отсутствовал в базовой линии первого запуска",
                    Severity.INFO,
                )
            )
    return out


def scan(state, config):
    return _scan_input(state, config) + _scan_ptrace(state, config) + _scan_modules(state, config)
