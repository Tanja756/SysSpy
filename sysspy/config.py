import fnmatch
import os
from pathlib import Path


class Config:
    """Runtime configuration + allow/deny lists used to suppress noise."""

    def __init__(self):
        default_db = os.environ.get("SYSSPY_DB")
        if not default_db:
            base = Path("/var/lib/sysspy") if os.geteuid() == 0 else Path.home() / ".sysspy"
            default_db = str(base / "sysspy.db")
        self.db_path = default_db

        # CPU% (over the measurement window) above which a process is flagged.
        self.cpu_idle_threshold = float(os.environ.get("SYSSPY_CPU", "25.0"))

        # Ports commonly associated with reverse shells / C2 frameworks.
        self.suspicious_ports = {
            4444, 31337, 6667, 1337, 9001, 1234, 31338, 1592,
            4445, 6666, 8443, 1080, 9999, 1338, 2345,
        }

        # Directories that should never host a running executable / dropped payload.
        self.suspicious_exe_paths = ["/tmp", "/var/tmp", "/dev/shm"]

        # Listener executables that may legitimately bind "suspicious" ports
        # (e.g. docker-proxy publishing a container port). Matched by substring.
        self.trusted_listeners = ("docker-proxy",)

        self.suspicious_exts = (
            ".so", ".ko", ".py", ".sh", ".elf", ".bin", ".service",
        )

        # Roots walked by the "recent files" / integrity scans.
        self.scan_roots = [
            "/bin", "/sbin", "/usr/bin", "/usr/sbin",
            "/lib", "/usr/lib", "/etc", "/opt", "/tmp", "/var", "/home",
        ]

        # (path, recursive) tuples watched by the filesystem observer.
        self.watch_dirs = [
            ("/tmp", True),
            ("/var/tmp", True),
            ("/dev/shm", False),
            ("/etc/systemd/system", False),
            ("/etc/cron.d", False),
            ("/etc/xdg/autostart", False),
            ("/usr/local/bin", False),
            ("/opt", True),
        ]

        # Kernel module name prefixes that are normally legitimate.
        self.ok_module_prefixes = (
            "vbox", "nvidia", "nouveau", "i915", "snd", "bt", "ath", "wl",
            "crypto", "ip_", "nf_", "xhci", "ahci", "ext4", "btrfs", "overlay",
            "bridge", "veth", "iptable", "usb", "tls", "cmac", "cfg80211",
        )

        # Пути/шаблоны, которые не должны попадать в находки (собственные
        # артефакты SysSpy, мусор тестов, высокоактивные системные логи).
        self.ignore_globs = [
            "*/sysspy_watch.log",
            "*/sysspy_report.html",
            "*/sysspy_report",
            "*/sysspy*.db",
            "/tmp/.pytest_cache/*",
            "/tmp/pytest-of-*",
            "/tmp/far2l_*",
            "/var/log/*",
            "/var/cache/*",
        ]

    def is_ignored(self, path):
        """Возвращает True, если путь совпадает с одним из шаблонов игнорирования."""
        if not path:
            return False
        for g in self.ignore_globs:
            if fnmatch.fnmatch(path, g) or fnmatch.fnmatch(os.path.abspath(path), g):
                return True
        return False
