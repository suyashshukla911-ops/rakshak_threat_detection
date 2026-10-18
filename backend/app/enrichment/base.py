from typing import Protocol

class ThreatIntelProvider(Protocol):
    name: str
    simulated: bool
    def lookup(self, ip: str) -> dict: ...
