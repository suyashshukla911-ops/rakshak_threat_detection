import json
from pathlib import Path

class DemoMockProvider:
    name = "demo-mock"
    simulated = True
    def __init__(self, fixture_path: str):
        self.data = json.loads(Path(fixture_path).read_text(encoding="utf-8"))
    def lookup(self, ip: str) -> dict:
        if ip in self.data:
            entry = dict(self.data[ip])
            entry.setdefault("provider", self.name)
            entry["simulated"] = True
            entry["available"] = True
            return entry
        return {
            "provider": self.name,
            "available": True,
            "simulated": True,
            "reputation": "unknown",
            "confidence": None,
            "report_count": 0,
            "country": "unknown",
        }

