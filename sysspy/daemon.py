import time

from .finding import Finding, Severity
from . import detectors, reporting


CADENCE = {
    "processes": 30,
    "network": 30,
    "persistence": 300,
    "filesystem": 300,
    "keylogger": 120,
    "integrity": 3600,
}

_SCAN_FUNCS = {
    "processes": detectors.processes.scan,
    "network": detectors.network.scan,
    "persistence": detectors.persistence.scan,
    "filesystem": detectors.filesystem.scan,
    "keylogger": detectors.keylogger.scan,
    "integrity": detectors.integrity.check,
}


def run_cycle(state, config):
    """Запускает все детекторы один раз, сохраняет находки, возвращает их."""
    findings = []
    for name, fn in _SCAN_FUNCS.items():
        if name == "integrity" and not state.get_kv("baseline_done"):
            continue
        try:
            fs = fn(state, config)
        except Exception as e:
            fs = [
                Finding(
                    "система",
                    f"Ошибка детектора: {name}",
                    str(e),
                    Severity.WARN,
                )
            ]
        findings.extend(fs)
    for f in findings:
        state.add_finding(f)
    return findings


def run(config, state, on_finding=None):
    """Цикл мониторинга на переднем плане. Вызывает on_finding(Finding) по мере событий."""
    observer = detectors.filesystem.start_watchdog(state, config)
    if observer is None:
        reporting.warn(
            "watchdog недоступен; используется периодическое сканирование файлов"
        )
    last = {}
    try:
        while True:
            now = time.time()
            for name, interval in CADENCE.items():
                if now - last.get(name, 0) >= interval:
                    last[name] = now
                    fn = _SCAN_FUNCS[name]
                    if name == "integrity" and not state.get_kv("baseline_done"):
                        continue
                    try:
                        fs = fn(state, config)
                    except Exception as e:
                        fs = [
                            Finding(
                                "система",
                                f"Ошибка детектора: {name}",
                                str(e),
                                Severity.WARN,
                            )
                        ]
                    for f in fs:
                        state.add_finding(f)
                        if on_finding:
                            on_finding(f)
            time.sleep(5)
    except KeyboardInterrupt:
        pass
    finally:
        if observer:
            observer.stop()
            observer.join()
