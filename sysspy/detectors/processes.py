import time

import psutil

from ..finding import Finding, Severity
from .. import utils

# Имена процессов, которые легитимно работают от root из нестандартных путей.
SYSTEM_NAMES = {"systemd", "init", "kthreadd"}


def scan(state, config):
    findings = []

    procs = []
    for p in psutil.process_iter(
        ["pid", "username", "cmdline", "exe", "cwd", "ppid", "uids", "status"]
    ):
        try:
            procs.append(p)
        except Exception:
            pass

    # Прогрев, чтобы cpu_percent() имел базу для сравнения.
    for p in procs:
        try:
            p.cpu_percent(None)
        except Exception:
            pass
    time.sleep(0.5)

    for p in procs:
        try:
            info = p.info
            pid = info["pid"]
            exe = info.get("exe") or ""
            cmd = " ".join(info.get("cmdline") or []) or "[ядро]"
            user = info.get("username") or ""
            cpu = p.cpu_percent(None)
            mem = p.memory_percent()
        except Exception:
            continue

        # Исполняемый файл в каталоге временных файлов / shared memory.
        if exe and any(exe.startswith(s) for s in config.suspicious_exe_paths):
            findings.append(
                Finding(
                    "процессы",
                    "Исполняемый файл в подозрительном расположении",
                    f"PID {pid} пользователь={user} exe={exe}\n    cmd={cmd[:200]}",
                    Severity.HIGH,
                )
            )

        # Высокая загрузка CPU, когда машина должна быть в простое.
        if cpu > config.cpu_idle_threshold:
            findings.append(
                Finding(
                    "процессы",
                    "Высокая загрузка CPU",
                    f"PID {pid} exe={exe} cpu={cpu:.1f}% mem={mem:.1f}% "
                    f"cmd={cmd[:150]}",
                    Severity.WARN,
                )
            )

        # Возможный live download-and-execute (curl|sh и т.п.).
        lc = cmd.lower()
        if ("curl" in lc or "wget" in lc) and ("|" in cmd or "sh" in lc or "bash" in lc):
            findings.append(
                Finding(
                    "процессы",
                    "Возможна загрузка и выполнение",
                    f"PID {pid} пользователь={user} cmd={cmd[:200]}",
                    Severity.HIGH,
                )
            )

        # Маскировка под системный компонент, но запущен откуда-то ещё.
        base = cmd.split()[0].rsplit("/", 1)[-1] if cmd not in ("", "[ядро]") else ""
        if base in SYSTEM_NAMES and exe and base not in exe:
            findings.append(
                Finding(
                    "процессы",
                    "Процесс маскируется под системный компонент",
                    f"PID {pid} cmd={cmd[:200]} exe={exe}",
                    Severity.HIGH,
                )
            )

    # Эвристика скрытых процессов: PID есть в /proc, но отсутствуют в psutil.
    proc_pids = set(utils.iter_proc_pids())
    psutil_pids = set(psutil.pids())
    hidden = sorted(proc_pids - psutil_pids)
    if hidden:
        findings.append(
            Finding(
                "процессы",
                "Возможны скрытые процессы",
                f"PID в /proc, но отсутствующие в выводе psutil: {hidden[:60]}",
                Severity.WARN,
            )
        )

    return findings
