import glob
import os
import re
import subprocess

from ..finding import Finding, Severity


def _run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except Exception:
        return None


def _flag(text):
    """Возвращает список причин подозрительности, найденных в тексте."""
    reasons = []
    low = text.lower()
    if re.search(r"\bcurl\s|\bwget\s", text):
        reasons.append("загрузка(curl/wget)")
    if re.search(r"\|\s*(sh|bash|python3?|perl)\b", text):
        reasons.append("конвейер-в-интерпретатор")
    if "/tmp/" in low or "/dev/shm/" in low or "/var/tmp/" in low:
        reasons.append("ссылка-на-временный-путь")
    if "@reboot" in low:
        reasons.append("@reboot")
    if re.search(r"\b(nc|ncat|netcat)\b[^\n]*(-e\b|\d+\.\d+\.\d+\.\d+)", text):
        reasons.append("netcat-обратный-шелл")
    if re.search(r"base64\s+-?d|/dev/tcp/|/dev/udp/", text):
        reasons.append("шелл-трюки")
    return reasons


# Подстроки имён юнитов, входящих в дистрибутив и безопасных для пропуска.
TRUSTED_UNITS = (
    "cloud-init", "cloud-config", "cloud-final", "snapd", "snap.", "apt", "dpkg",
    "apport", "unattended-upgrades", "networkd", "NetworkManager", "systemd",
    "udev", "user@", "session", "getty", "dbus", "rsyslog", "cron", "ssh",
)


def _scan_systemd(config):
    out = []
    r = _run(
        ["systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager"]
    )
    if not r or r.returncode != 0:
        return out
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        name, state = parts[0], parts[1]
        if any(t in name for t in TRUSTED_UNITS):
            continue
        show = _run(["systemctl", "show", name, "-p", "FragmentPath", "-p", "ExecStart"])
        if not show:
            continue
        frag = execstart = ""
        for l in show.stdout.splitlines():
            if l.startswith("FragmentPath="):
                frag = l.split("=", 1)[1]
            elif l.startswith("ExecStart="):
                execstart = l.split("=", 1)[1]
        reasons = _flag(f"{frag} {execstart}")
        distro = frag.startswith(("/usr/lib/systemd/system/", "/lib/systemd/system/"))
        if (not distro) or reasons:
            if any(s in frag for s in config.suspicious_exe_paths) or reasons:
                out.append(
                    Finding(
                        "автозагрузка",
                        "Подозрительный systemd-юнит",
                        f"{name} [{state}] frag={frag}\n    exec={execstart[:200]}\n"
                        f"    причины={reasons}",
                        Severity.HIGH if reasons or frag else Severity.INFO,
                    )
                )
    return out


def _scan_cron(config):
    out = []
    if os.path.isfile("/etc/crontab"):
        with open("/etc/crontab") as f:
            t = f.read()
        rs = _flag(t)
        if rs:
            out.append(
                Finding(
                    "автозагрузка",
                    "Подозрительный /etc/crontab",
                    f"причины={rs}\n{t[:400]}",
                    Severity.HIGH,
                )
            )
    for p in glob.glob("/etc/cron.d/*"):
        if os.path.isfile(p):
            with open(p) as f:
                t = f.read()
            rs = _flag(t)
            if rs:
                out.append(
                    Finding(
                        "автозагрузка",
                        f"Подозрительный {p}",
                        f"причины={rs}\n{t[:400]}",
                        Severity.HIGH,
                    )
                )
    spool = "/var/spool/cron/crontabs"
    if os.path.isdir(spool):
        try:
            users_cron = os.listdir(spool)
        except Exception:
            users_cron = []
        for u in users_cron:
            fp = os.path.join(spool, u)
            if os.path.isfile(fp):
                try:
                    with open(fp) as f:
                        t = f.read()
                except Exception:
                    continue
                rs = _flag(t)
                if rs:
                    out.append(
                        Finding(
                            "автозагрузка",
                            f"Подозрительный crontab (пользователь={u})",
                            f"причины={rs}\n{t[:400]}",
                            Severity.HIGH,
                        )
                    )
    users = ["root"] + [u for u in os.listdir("/home") if os.path.isdir(f"/home/{u}")]
    for u in users:
        r = _run(["crontab", "-l", "-u", u])
        if r and r.returncode == 0 and r.stdout.strip():
            rs = _flag(r.stdout)
            if rs:
                out.append(
                    Finding(
                        "автозагрузка",
                        f"Подозрительный crontab -l (пользователь={u})",
                        f"причины={rs}\n{r.stdout[:400]}",
                        Severity.HIGH,
                    )
                )
    return out


def _scan_rc(config):
    out = []
    files = ["/etc/profile", "/etc/bash.bashrc"]
    files += glob.glob("/etc/profile.d/*")
    users = ["root"] + [u for u in os.listdir("/home") if os.path.isdir(f"/home/{u}")]
    for u in users:
        home = "/root" if u == "root" else f"/home/{u}"
        for rc in (".bashrc", ".profile", ".bash_profile"):
            fp = os.path.join(home, rc)
            if os.path.isfile(fp):
                files.append(fp)

    for fp in files:
        try:
            with open(fp) as f:
                t = f.read()
        except Exception:
            continue
        rs = _flag(t)
        if rs:
            out.append(
                Finding(
                    "автозагрузка",
                    f"Подозрительный shell-rc {fp}",
                    f"причины={rs}\n{t[:400]}",
                    Severity.HIGH,
                )
            )

    autodirs = ["/etc/xdg/autostart"]
    for u in users:
        autodirs.append(f"/home/{u}/.config/autostart")
    autodirs.append("/root/.config/autostart")
    for d in autodirs:
        for dp in glob.glob(os.path.join(d, "*.desktop")):
            try:
                with open(dp) as f:
                    t = f.read()
            except Exception:
                continue
            exec_line = ""
            for line in t.splitlines():
                if line.startswith("Exec="):
                    exec_line = line[5:]
            rs = _flag(t)
            if rs or any(s in exec_line for s in config.suspicious_exe_paths):
                out.append(
                    Finding(
                        "автозагрузка",
                        f"Подозрительный autostart {dp}",
                        f"причины={rs} exec={exec_line[:200]}",
                        Severity.HIGH,
                    )
                )
    return out


def scan(state, config):
    return _scan_systemd(config) + _scan_cron(config) + _scan_rc(config)
