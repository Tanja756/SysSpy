import psutil

from ..finding import Finding, Severity
from .. import utils

# Порты, обычно легитимные (web/dns/ssh/mail/db). Соединения на них от
# доверенных бинарников не стоит помечать INFO при каждом скане.
COMMON_PORTS = {80, 443, 53, 123, 22, 25, 465, 587, 993, 995, 3306, 5432, 6379, 8080}
TRUSTED_EXE = ("/usr/", "/snap/", "/opt/", "/lib/", "/bin/", "/sbin/", "/var/lib/")


def scan(state, config):
    findings = []
    first_run = state.count_connections() == 0

    try:
        conns = psutil.net_connections(kind="inet")
    except Exception as e:
        findings.append(
            Finding(
                "сеть",
                "Не удалось получить список соединений",
                f"{e} (запустите с sudo)",
                Severity.WARN,
            )
        )
        return findings

    for c in conns:
        pid = c.pid
        status = c.status
        laddr = c.laddr
        raddr = c.raddr
        lip = laddr.ip if laddr else None
        lport = laddr.port if laddr else None
        rip = raddr.ip if raddr else None
        rport = raddr.port if raddr else None
        exe = utils.exe_of_pid(pid) if pid else None

        if status == "LISTEN":
            plabel = f"PID {pid} {exe}" if pid else "PID неизвестен (запустите с sudo)"
            ctx = utils.proc_context(pid) if pid else ""
            if exe and any(s in exe for s in config.trusted_listeners):
                continue
            if lport and lport in config.suspicious_ports:
                findings.append(
                    Finding(
                        "сеть",
                        "Подозрительный прослушиваемый порт",
                        f"{plabel} слушает на :{lport} {ctx}".rstrip(),
                        Severity.HIGH,
                    )
                )
            if exe and any(exe.startswith(s) for s in config.suspicious_exe_paths):
                findings.append(
                    Finding(
                        "сеть",
                        "Слушающий сокет из подозрительного расположения",
                        f"{plabel} слушает на :{lport} {ctx}".rstrip(),
                        Severity.HIGH,
                    )
                )
            continue

        if status == "ESTABLISHED" and rip:
            key = f"{pid}:{rip}:{rport}"
            known = state.remember_connection(key)

            if utils.is_local_ip(rip):
                continue

            conn = f"PID {pid} {exe or '?'} -> {rip}:{rport} ({status})"
            ctx = utils.proc_context(pid) if pid else ""
            if rport in config.suspicious_ports:
                findings.append(
                    Finding(
                        "сеть",
                        "Подозрительный внешний порт",
                        f"{conn} {ctx}".rstrip(),
                        Severity.HIGH,
                    )
                )
                continue
            if exe and any(exe.startswith(s) for s in config.suspicious_exe_paths):
                findings.append(
                    Finding(
                        "сеть",
                        "Внешнее соединение из подозрительного расположения",
                        f"{conn} {ctx}".rstrip(),
                        Severity.HIGH,
                    )
                )
                continue
            if not known and not first_run:
                noisy = rport in COMMON_PORTS and (not exe or exe.startswith(TRUSTED_EXE))
                if not noisy:
                    findings.append(
                        Finding(
                            "сеть",
                            "Новое внешнее соединение",
                            f"{conn} {ctx}".rstrip(),
                            Severity.INFO,
                        )
                    )

    return findings
