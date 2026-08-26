import os

from ..finding import Finding, Severity
from .. import utils

_EXE_ROOTS = ("/bin", "/sbin", "/usr/bin", "/usr/sbin")


def _collect_targets(config):
    targets = []
    for root in _EXE_ROOTS:
        if not os.path.isdir(root):
            continue
        for dp, dns, fns in os.walk(root):
            if dp.startswith(("/proc", "/sys", "/dev", "/run")):
                dns[:] = []
                continue
            for fn in fns:
                targets.append(os.path.join(dp, fn))
    if os.path.isdir("/etc"):
        for dp, dns, fns in os.walk("/etc"):
            if dp.startswith(("/proc", "/sys", "/dev", "/run")):
                dns[:] = []
                continue
            for fn in fns:
                targets.append(os.path.join(dp, fn))
    for root in ("/lib", "/usr/lib"):
        if not os.path.isdir(root):
            continue
        for dp, dns, fns in os.walk(root):
            if dp.startswith(("/proc", "/sys", "/dev", "/run")):
                dns[:] = []
                continue
            for fn in fns:
                if fn.endswith(".so"):
                    targets.append(os.path.join(dp, fn))
    return targets


def init_baseline(state, config):
    pairs = []
    for path in _collect_targets(config):
        h = utils.file_sha256(path)
        if h:
            try:
                mtime = os.path.getmtime(path)
            except Exception:
                mtime = 0
            pairs.append(("integ:" + path, f"{h}|{mtime}"))
    state.bulk_kv(pairs)
    state.set_kv("baseline_done", "1")
    return len(pairs)


def check(state, config):
    findings = []
    for path in _collect_targets(config):
        try:
            mtime = os.path.getmtime(path)
        except Exception:
            mtime = None
        old = state.get_kv("integ:" + path)
        if old is None:
            h = utils.file_sha256(path)
            if h is None:
                continue
            state.set_kv("integ:" + path, f"{h}|{mtime}")
            findings.append(
                Finding(
                    "целостность",
                    "Новый файл (не в базовой линии)",
                    f"{path}",
                    Severity.WARN,
                )
            )
            continue
        try:
            old_h, old_mtime = old.split("|", 1)
        except Exception:
            old_h, old_mtime = old, None
        # Неизмененный mtime => содержимое не менялось, пропускаем хеширование.
        if old_mtime is not None and mtime is not None and str(mtime) == old_mtime:
            continue
        h = utils.file_sha256(path)
        if h is None:
            findings.append(
                Finding(
                    "целостность",
                    "Файл из базовой линии удалён",
                    f"{path} был в базовой линии, но теперь отсутствует",
                    Severity.WARN,
                )
            )
            continue
        if old_h != h:
            findings.append(
                Finding(
                    "целостность",
                    "Файл изменён с момента создания базовой линии",
                    f"{path} хеш изменился",
                    Severity.HIGH,
                )
            )
    return findings
