"""
Finding data model - each vulnerability/misconfiguration gets one of these.
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional
import json


@dataclass
class Finding:
    title: str
    severity: str
    resource_type: str
    resource_id: str
    description: str
    remediation: str
    scanner: str
    region: str = ""
    account_id: str = ""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    ai_analysis: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class FindingCollection:
    """Holds all findings from a scan run."""

    def __init__(self):
        self.findings: list[Finding] = []

    def add(self, finding: Finding):
        self.findings.append(finding)

    def get_by_severity(self, severity: str) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]

    @property
    def critical_count(self) -> int:
        return len(self.get_by_severity("CRITICAL"))

    @property
    def high_count(self) -> int:
        return len(self.get_by_severity("HIGH"))

    def summary(self) -> dict:
        from collections import Counter
        sevs = Counter(f.severity for f in self.findings)
        return {
            "total": len(self.findings),
            "critical": sevs.get("CRITICAL", 0),
            "high": sevs.get("HIGH", 0),
            "medium": sevs.get("MEDIUM", 0),
            "low": sevs.get("LOW", 0),
            "info": sevs.get("INFO", 0),
        }

    def to_json(self) -> str:
        return json.dumps([f.to_dict() for f in self.findings], indent=2)
