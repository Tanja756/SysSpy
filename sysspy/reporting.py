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
