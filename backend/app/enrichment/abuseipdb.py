import asyncio
import ipaddress
import json
from pathlib import Path
import sqlite3
import time
import httpx
from app.core.config import settings

def _get_sqlite_path() -> Path:
    db_url = settings.database_url
    if db_url.startswith("sqlite:///"):
        raw_path = db_url.replace("sqlite:///", "")
        return Path(raw_path)
    return Path(__file__).resolve().parents[3] / "rakshak.db"

class AbuseIPDBProvider:
    name = "abuseipdb"
    simulated = False

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key if api_key is not None else settings.abuseipdb_api_key
        self.db_path = _get_sqlite_path()
        self._init_cache_table()

    def _init_cache_table(self):
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS threat_intel_cache (
                        ip TEXT PRIMARY KEY,
                        cached_at REAL,
                        data TEXT
                    )
                """)
                conn.commit()
        except Exception:
            pass

    def _get_cached(self, ip: str) -> dict | None:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cur = conn.cursor()
                cur.execute("SELECT cached_at, data FROM threat_intel_cache WHERE ip = ?", (ip,))
                row = cur.fetchone()
                if row:
                    cached_at, data_str = row
                    if time.time() - cached_at < 86400:
                        return json.loads(data_str)
        except Exception:
            pass
        return None

    def _set_cached(self, ip: str, data: dict):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO threat_intel_cache (ip, cached_at, data) VALUES (?, ?, ?)",
                    (ip, time.time(), json.dumps(data))
                )
                conn.commit()
        except Exception:
            pass

    def _check_ip(self, ip: str) -> dict | None:
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local:
                return {
                    "provider": self.name,
                    "available": False,
                    "simulated": False,
                    "reputation": "unknown",
                    "confidence": None,
                    "report_count": 0,
                    "country": "internal",
                    "reason": "private_or_reserved",
                }
        except ValueError:
            return {
                "provider": self.name,
                "available": False,
                "simulated": False,
                "reputation": "unknown",
                "confidence": None,
                "report_count": 0,
                "country": "unknown",
                "reason": "invalid_ip",
            }
        return None

    def lookup(self, ip: str) -> dict:
        check = self._check_ip(ip)
        if check:
            return check

        cached = self._get_cached(ip)
        if cached:
            return cached

        if not self.api_key:
            return {
                "provider": self.name,
                "available": False,
                "simulated": False,
                "reputation": "unknown",
                "confidence": None,
                "report_count": 0,
                "country": "unknown",
                "reason": "Threat intel: unavailable",
            }

        url = "https://api.abuseipdb.com/api/v2/check"
        for attempt in range(3):
            try:
                with httpx.Client(timeout=5.0) as client:
                    r = client.get(
                        url,
                        params={"ipAddress": ip, "maxAgeInDays": 90},
                        headers={"Key": self.api_key, "Accept": "application/json"}
                    )
                    r.raise_for_status()
                    data = r.json().get("data", {})
                    score = data.get("abuseConfidenceScore", 0)
                    result = {
                        "provider": self.name,
                        "available": True,
                        "simulated": False,
                        "reputation": score,
                        "confidence": score,
                        "report_count": data.get("totalReports", 0),
                        "country": data.get("countryCode") or "unknown",
                    }
                    self._set_cached(ip, result)
                    return result
            except Exception:
                if attempt == 2:
                    break
                time.sleep(0.5 * (2 ** attempt))

        return {
            "provider": self.name,
            "available": False,
            "simulated": False,
            "reputation": "unknown",
            "confidence": None,
            "report_count": 0,
            "country": "unknown",
            "reason": "Threat intel: unavailable",
        }

    async def lookup_async(self, ip: str) -> dict:
        check = self._check_ip(ip)
        if check:
            return check

        cached = self._get_cached(ip)
        if cached:
            return cached

        if not self.api_key:
            return {
                "provider": self.name,
                "available": False,
                "simulated": False,
                "reputation": "unknown",
                "confidence": None,
                "report_count": 0,
                "country": "unknown",
                "reason": "Threat intel: unavailable",
            }

        url = "https://api.abuseipdb.com/api/v2/check"
        for attempt in range(3):
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    r = await client.get(
                        url,
                        params={"ipAddress": ip, "maxAgeInDays": 90},
                        headers={"Key": self.api_key, "Accept": "application/json"}
                    )
                    r.raise_for_status()
                    data = r.json().get("data", {})
                    score = data.get("abuseConfidenceScore", 0)
                    result = {
                        "provider": self.name,
                        "available": True,
                        "simulated": False,
                        "reputation": score,
                        "confidence": score,
                        "report_count": data.get("totalReports", 0),
                        "country": data.get("countryCode") or "unknown",
                    }
                    self._set_cached(ip, result)
                    return result
            except Exception:
                if attempt == 2:
                    break
                await asyncio.sleep(0.5 * (2 ** attempt))

        return {
            "provider": self.name,
            "available": False,
            "simulated": False,
            "reputation": "unknown",
            "confidence": None,
            "report_count": 0,
            "country": "unknown",
            "reason": "Threat intel: unavailable",
        }

