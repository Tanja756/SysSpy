import json
import logging
import logging.handlers
import os

from rich.console import Console
from rich.text import Text

from .finding import Severity

console = Console()

SEV_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.WARN: 2,
    Severity.INFO: 3,
}

# (стиль тега, русская метка) для каждого уровня
SEV_STYLE = {
    Severity.CRITICAL: ("bold white on red", "КРИТИЧ"),
    Severity.HIGH: ("bold red", "ВЫСОКИЙ"),
    Severity.WARN: ("bold yellow", "ПРЕДУПР"),
    Severity.INFO: ("bold cyan", "ИНФО"),
}


def _sort(findings):
    return sorted(findings, key=lambda f: SEV_ORDER.get(f.severity, 9))


def _sev_style(sev):
    return SEV_STYLE.get(sev, ("white", str(sev.value)))


def print_finding(f, compact=True):
    style, label = _sev_style(f.severity)
    t = Text()
    t.append(f"[{label}] ", style=style)
    t.append(f"{f.category}: ", style="bold")
    t.append(f.title, style="italic")
    if compact:
        t.append(" :: ", style="dim")
        t.append(f.detail[:160], style="dim")
    console.print(t)
    if not compact:
        console.print(Text(f"    {f.detail}", style="dim"))
        console.print(Text(f"    ({f.timestamp})", style="dim cyan"))


def print_findings(findings):
    if not findings:
        console.print(Text("Находок нет.", style="green"))
        return
    for f in _sort(findings):
        print_finding(f, compact=False)
        console.print()


def banner(msg):
    console.print(Text("[sysspy] ", style="bold green") + Text(msg, style="dim"))


def info(msg):
    console.print(Text("[sysspy] ", style="bold green") + Text(msg, style="dim"))


def warn(msg):
    console.print(Text("[sysspy] ", style="bold yellow") + Text(msg, style="yellow"))


# --------------------------------------------------------------------------- #
# Файловый лог для внешнего анализа (JSON-строки, ротация по размеру)
# --------------------------------------------------------------------------- #

file_logger = logging.getLogger("sysspy.file")
_file_log_enabled = False


class _JsonFormatter(logging.Formatter):
    def format(self, record):
        payload = getattr(record, "payload", None)
        obj = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
        }
        if payload:
            obj.update(payload)
        else:
            obj["message"] = record.getMessage()
        return json.dumps(obj, ensure_ascii=False)


def setup_file_log(path, verbose=False, max_bytes=5 * 1024 * 1024, backups=3):
    """Включить запись событий в файл (JSON-строки) с ротацией по размеру.

    verbose=True добавляет отладочные события (detector_run и т.п.).
    """
    global _file_log_enabled
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    for h in list(file_logger.handlers):
        file_logger.removeHandler(h)
    handler = logging.handlers.RotatingFileHandler(
        path, maxBytes=max_bytes, backupCount=backups, encoding="utf-8"
    )
    handler.setFormatter(_JsonFormatter())
    file_logger.addHandler(handler)
    file_logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    file_logger.propagate = False
    _file_log_enabled = True


def _emit(level, payload):
    if not _file_log_enabled:
        return
    file_logger.log(level, "event", extra={"payload": payload})


def log_finding(f):
    _emit(
        logging.INFO,
        {
            "event": "finding",
            "severity": f.severity.value,
            "category": f.category,
            "title": f.title,
            "detail": f.detail,
            "timestamp": f.timestamp,
        },
    )


def log_event(level, event, **data):
    lvl = {
        "debug": logging.DEBUG,
        "info": logging.INFO,
        "warning": logging.WARNING,
        "error": logging.ERROR,
    }.get(level, logging.INFO)
    payload = {"event": event}
    payload.update(data)
    _emit(lvl, payload)


def render_text(findings):
    if not findings:
        return "Находок нет."
    lines = []
    for f in _sort(findings):
        lines.append(
            f"[{f.severity.value}] {f.category} | {f.title}\n    {f.detail}\n"
            f"    ({f.timestamp})"
        )
    return "\n".join(lines)


def render_html(findings, title="Отчёт SysSpy"):
    body = []
    for f in _sort(findings):
        color = {
            Severity.CRITICAL: "#b00",
            Severity.HIGH: "#d63",
            Severity.WARN: "#c90",
            Severity.INFO: "#369",
        }.get(f.severity, "#000")
        body.append(
            f'<div style="border-left:4px solid {color}; padding:4px 8px; '
            f'margin:6px 0;">'
            f"<b>[{f.severity.value}] {f.category}</b> — {f.title}<br/>"
            f"<span style='white-space:pre-wrap'>{f.detail}</span><br/>"
            f"<small>{f.timestamp}</small></div>"
        )
    return (
        f"<html><head><meta charset='utf-8'><title>{title}</title></head>"
        f"<body><h1>{title}</h1>{''.join(body)}</body></html>"
    )
