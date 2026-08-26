import argparse
import os
import sys
import time

from .config import Config
from .state import State
from . import detectors, reporting, daemon


def _project_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _state(config):
    return State(config.db_path)


def cmd_scan(args, config):
    state = _state(config)
    reporting.log_event("info", "scan_start", db=config.db_path)
    findings = daemon.run_cycle(state, config)
    _print_summary(findings, state)
    state.close()


def cmd_watch(args, config):
    state = _state(config)
    reporting.console.rule("[bold green]SysSpy — мониторинг[/]")
    reporting.banner(
        f"мониторинг запущен (БД={config.db_path}); Ctrl-C для остановки"
    )
    reporting.log_event("info", "monitor_start", db=config.db_path)
    daemon.run(
        config,
        state,
        on_finding=lambda f: (
            reporting.print_finding(f, compact=True),
            reporting.log_finding(f),
        ),
    )
    reporting.log_event("info", "monitor_stop")
    state.close()


def cmd_status(args, config):
    state = _state(config)
    counts = state.count_findings()
    reporting.console.print("Находки по уровням:", counts or "нет")
    findings = state.recent_findings(limit=40)
    reporting.print_findings(findings)
    state.close()


def cmd_report(args, config):
    state = _state(config)
    since = None
    if args.days:
        since = time.strftime(
            "%Y-%m-%dT%H:%M:%S", time.localtime(time.time() - args.days * 86400)
        )
    findings = state.recent_findings(limit=5000, since=since)
    if args.html:
        with open(args.html, "w") as f:
            f.write(reporting.render_html(findings))
        reporting.console.print(
            f"HTML-отчёт записан в {args.html} (находок: {len(findings)})",
            style="green",
        )
    else:
        reporting.print_findings(findings)
    state.close()


def cmd_baseline(args, config):
    state = _state(config)
    if args.action == "init":
        n = detectors.integrity.init_baseline(state, config)
        reporting.console.print(
            f"Базовая линия целостности создана для {n} файлов.", style="green"
        )
    else:
        findings = detectors.integrity.check(state, config)
        _print_summary(findings, state)
    state.close()


def cmd_cleandb(args, config):
    state = _state(config)
    if not args.yes:
        ans = input(
            f"Удалить ВСЕ находки и базовые линии из {config.db_path}? [y/N] "
        )
        if ans.lower() not in ("y", "yes", "д", "да"):
            reporting.console.print("Отменено.", style="yellow")
            state.close()
            return
    n = state.clear()
    reporting.console.print(
        f"База очищена: удалено записей — {n}. Базовую линию целостности "
        f"нужно создать заново (baseline init).",
        style="green",
    )
    state.close()


def cmd_service(args, config):
    unit = f"""[Unit]
Description=Демон мониторинга SysSpy
After=network.target

[Service]
Type=simple
ExecStart={sys.executable} -m sysspy watch
WorkingDirectory={_project_root()}
Environment=PYTHONPATH={_project_root()}
Environment=SYSSPY_DB={config.db_path}
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
"""
    path = "/etc/systemd/system/sysspy.service"
    if args.action == "install":
        if os.geteuid() != 0:
            reporting.console.print(
                "установка сервиса требует root (sudo)", style="red"
            )
            return
        with open(path, "w") as f:
            f.write(unit)
        os.system("systemctl daemon-reload")
        reporting.console.print(
            f"Записан {path}. Включить: sudo systemctl enable --now sysspy",
            style="green",
        )
    else:
        os.system(f"systemctl {args.action} sysspy")


def _print_summary(findings, state):
    if not findings:
        reporting.console.print(
            "В этом запуске подозрительного не найдено.", style="green"
        )
        return
    reporting.print_findings(findings)
    for f in findings:
        reporting.log_finding(f)
    counts = state.count_findings()
    reporting.console.print("\nИтого в БД по уровням:", counts)


def build_parser():
    p = argparse.ArgumentParser(
        prog="sysspy", description="Лёгкий детектор шпионского ПО / вторжений для Linux"
    )
    p.add_argument("--db", default=None, help="путь к базе SQLite")
    p.add_argument(
        "--log", default=None, metavar="FILE",
        help="записывать события в файл (JSON-строки) для внешнего анализа",
    )
    p.add_argument(
        "--verbose", action="store_true",
        help="подробный лог: включать отладочные события (detector_run и т.п.)",
    )
    p.add_argument(
        "--log-size", type=int, default=5 * 1024 * 1024,
        help="максимальный размер лог-файла в байтах до ротации (по умолчанию 5 МБ)",
    )
    p.add_argument(
        "--log-backups", type=int, default=3,
        help="число хранимых ротированных копий лога (по умолчанию 3)",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("scan", help="запустить все детекторы один раз и сохранить находки")
    sub.add_parser("watch", help="запустить цикл мониторинга на переднем плане")
    sub.add_parser("status", help="показать последние находки из базы")
    rp = sub.add_parser("report", help="сформировать отчёт")
    rp.add_argument("--html", default=None, help="записать HTML-отчёт в этот файл")
    rp.add_argument("--days", type=int, default=7, help="охватить N дней")
    bl = sub.add_parser("baseline", help="управление базовой линией целостности")
    bl.add_argument("action", choices=["init", "check"])
    sv = sub.add_parser("service", help="управление systemd-сервисом")
    sv.add_argument("action", choices=["install", "start", "stop", "status"])
    cd = sub.add_parser("cleandb", help="полностью очистить базу данных (находки и базовые линии)")
    cd.add_argument("--yes", action="store_true", help="не запрашивать подтверждение")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    config = Config()
    if args.db:
        config.db_path = args.db
    if args.log:
        reporting.setup_file_log(
            args.log,
            verbose=args.verbose,
            max_bytes=args.log_size,
            backups=args.log_backups,
        )
        reporting.log_event("info", "start", command=args.cmd, db=config.db_path)
    dispatch = {
        "scan": cmd_scan,
        "watch": cmd_watch,
        "status": cmd_status,
        "report": cmd_report,
        "baseline": cmd_baseline,
        "service": cmd_service,
        "cleandb": cmd_cleandb,
    }
    dispatch[args.cmd](args, config)


if __name__ == "__main__":
    main()
