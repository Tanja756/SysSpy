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

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat(timespec="seconds")
        if not isinstance(self.severity, Severity):
            self.severity = Severity(self.severity)
