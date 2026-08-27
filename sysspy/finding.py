from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    INFO = "ИНФО"
    WARN = "ПРЕДУПР"
    HIGH = "ВЫСОКИЙ"
    CRITICAL = "КРИТИЧ"


@dataclass
class Finding:
    category: str
    title: str
    detail: str
    severity: Severity = Severity.INFO
    timestamp: str = None
    key: str = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat(timespec="seconds")
        if not isinstance(self.severity, Severity):
            self.severity = Severity(self.severity)

    def identity(self) -> str:
        """Стабильный ключ для дедупликации повторяющихся находок.

        Если детектор задал явный ``key`` (например, по PID или пути), он
        имеет приоритет. Иначе используется комбинация полей — этого
        достаточно, чтобы одна и та же логическая находка не дублировалась
        на каждом цикле мониторинга.
        """
        if self.key:
            return self.key
        return f"{self.category}|{self.title}|{self.detail}"
