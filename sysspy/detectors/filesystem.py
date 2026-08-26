import os
import time

from ..finding import Finding, Severity
from .. import utils

try:
    from watchdog.events import FileSystemEventHandler

    class _Handler(FileSystemEventHandler):
        def __init__(self, state, config):
            self.state = state
            self.config = config

        def _check(self, path):
            if not os.path.isfile(path):
                return
            if any(path.startswith(p) for p in ("/proc", "/sys", "/dev", "/run")):
                return
            reasons = []
            if any(path.startswith(s) for s in self.config.suspicious_exe_paths):
                reasons.append("временный-путь")
            ext = os.path.splitext(path)[1].lower()
            if ext in self.config.suspicious_exts:
                reasons.append("подозрительное-расширение")
            try:
                if os.access(path, os.X_OK):
                    reasons.append("исполняемый")
            except Exception:
                pass
            if reasons:
                self.state.add_finding(
                    Finding(
                        "файлы",
                        "Подозрительное событие с файлом",
                        f"{path} причины={reasons}",
                        Severity.HIGH,
                    )
                )

        def on_created(self, event):
            if not event.is_directory:
                self._check(event.src_path)

        def on_modified(self, event):
            if not event.is_directory:
                self._check(event.src_path)

except ImportError:

    class _Handler:
        def __init__(self, state, config):
            self.state = state
            self.config = config

        def _check(self, path):
            if not os.path.isfile(path):
                return
            if any(path.startswith(p) for p in ("/proc", "/sys", "/dev", "/run")):
                return
            reasons = []
            if any(path.startswith(s) for s in self.config.suspicious_exe_paths):
                reasons.append("временный-путь")
            ext = os.path.splitext(path)[1].lower()
            if ext in self.config.suspicious_exts:
                reasons.append("подозрительное-расширение")
            try:
                if os.access(path, os.X_OK):
                    reasons.append("исполняемый")
            except Exception:
                pass
            if reasons:
                self.state.add_finding(
                    Finding(
                        "файлы",
                        "Подозрительное событие с файлом",
                        f"{path} причины={reasons}",
                        Severity.HIGH,
                    )
                )

        def on_created(self, path):
            self._check(path)

        def on_modified(self, path):
            self._check(path)


def _watch_paths(config):
    dirs = list(config.watch_dirs)
    for u in os.listdir("/home") if os.path.isdir("/home") else []:
        d = os.path.join("/home", u, ".config", "autostart")
        if os.path.isdir(d):
            dirs.append((d, False))
    if os.path.isdir("/root/.config/autostart"):
        dirs.append(("/root/.config/autostart", False))
    return dirs


def start_watchdog(state, config):
    """Запуск real-time слежения за файлами (требует `watchdog`). Возвращает observer или None."""
    try:
        from watchdog.observers import Observer
    except ImportError:
        return None
    observer = Observer()
    handler = _Handler(state, config)
    for path, rec in _watch_paths(config):
        if os.path.isdir(path):
            observer.schedule(handler, path, recursive=rec)
    observer.daemon = True
    observer.start()
    return observer


def scan(state, config, days=1):
    """Периодический скан недавно созданных/изменённых файлов.

    Намеренно узкий, чтобы не шуметь: флагает только исполняемые файлы,
    появившиеся в системных каталогах, либо любую активность во временных
    каталогах. Домашние каталоги исключены (их покрывает real-time слежение
    за autostart-каталогами)."""
    findings = []
    now = time.time()
    cutoff = now - days * 86400
    sys_roots = ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/lib", "/opt"]
    for root in sys_roots + config.suspicious_exe_paths:
        if not os.path.isdir(root):
            continue
        for dp, dns, fns in os.walk(root):
            if dp.startswith(("/proc", "/sys", "/dev", "/run")):
                dns[:] = []
                continue
            for fn in fns:
                path = os.path.join(dp, fn)
                try:
                    st = os.lstat(path)
                except Exception:
                    continue
                if st.st_mtime <= cutoff and st.st_ctime <= cutoff:
                    continue
                ext = os.path.splitext(fn)[1].lower()
                in_temp = any(path.startswith(s) for s in config.suspicious_exe_paths)
                executable = False
                try:
                    executable = os.access(path, os.X_OK)
                except Exception:
                    pass
                if in_temp:
                    hidden = os.path.basename(path).startswith(".")
                    dropper = ext in (".so", ".sh", ".elf", ".bin", ".py", ".ko")
                    sev = Severity.HIGH if (executable or hidden or dropper) else Severity.WARN
                    findings.append(
                        Finding(
                            "файлы",
                            "Недавняя активность во временном каталоге",
                            f"mtime={time.ctime(st.st_mtime)} {path}",
                            sev,
                        )
                    )
                elif executable:
                    findings.append(
                        Finding(
                            "файлы",
                            "Новый/изменённый исполняемый файл в системном каталоге",
                            f"mtime={time.ctime(st.st_mtime)} {path}",
                            Severity.WARN,
                        )
                    )
    return findings
