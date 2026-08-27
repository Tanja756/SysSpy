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
        reporting.log_event("debug", "detector_run", detector=name)
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


def _emit(f, seen, state, on_finding):
    """Обрабатывает одну находку: логирует всегда, дедуплицирует вывод/БД.

    JSON-лог (``reporting.log_finding``) получает ВСЕ вхождения. Консоль и БД
    получают находку только при первом появлении либо при эскалации уровня —
    повторы одной и той же логической находки не дублируются.
    """
    reporting.log_finding(f)
    k = f.identity()
    rec = seen.get(k)
    if rec is None:
        seen[k] = {
            "first": f.timestamp,
            "last": f.timestamp,
            "count": 1,
            "sev": f.severity,
        }
        state.add_finding(f)
        if on_finding:
            on_finding(f)
        return
    rec["last"] = f.timestamp
    rec["count"] += 1
    if reporting.SEV_ORDER[f.severity] < reporting.SEV_ORDER[rec["sev"]]:
        rec["sev"] = f.severity
        if on_finding:
            on_finding(f)


def run(config, state, on_finding=None, summary_every=12):
    """Цикл мониторинга на переднем плане. Вызывает on_finding(Finding) по мере событий.

    Повторяющиеся находки (один и тот же ``identity()``) печатаются и пишутся
    в БД только при первом появлении; последующие вхождения тихо учитываются
    в сводке, но не дублируют вывод. JSON-лог (``reporting.log_finding``) при
    этом получает ВСЕ вхождения — для внешней системы анализа важна полнота.
    """
    observer = detectors.filesystem.start_watchdog(state, config)
    if observer is None:
        reporting.warn(
            "watchdog недоступен; используется периодическое сканирование файлов"
        )
    last = {}
    seen = {}
    cycle = 0
    try:
        while True:
            now = time.time()
            for name, interval in CADENCE.items():
                if now - last.get(name, 0) >= interval:
                    last[name] = now
                    reporting.log_event("debug", "detector_run", detector=name)
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
                        _emit(f, seen, state, on_finding)
            cycle += 1
            if summary_every and cycle % summary_every == 0:
                reporting.print_watch_summary(seen)
            time.sleep(5)
    except KeyboardInterrupt:
        pass
    finally:
        if observer:
            observer.stop()
            observer.join()
