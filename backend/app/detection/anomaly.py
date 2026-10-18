from __future__ import annotations
from collections import defaultdict
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from app.core.config import settings

class AnomalyEngine:
    def __init__(self):
        self.model = None
        self.status = "unavailable"
        self._load()

    def _load(self):
        path = Path(settings.anomaly_model_path)
        try:
            if path.exists():
                self.model = joblib.load(path)
                self.status = "ready"
        except Exception:
            self.model = None
            self.status = "unavailable"

    @staticmethod
    def features(events: list[dict]) -> pd.DataFrame:
        buckets = defaultdict(list)
        for e in events:
            ip = e.get("source_ip")
            if not ip:
                continue
            ts = pd.Timestamp(e["timestamp"]).floor("min")
            buckets[(ip, ts)].append(e)
        rows = []
        for (source_ip, ts), vals in buckets.items():
            rows.append({
                "source_ip": source_ip or "none",
                "window": ts,
                "event_count": len(vals),
                "failed_login_count": sum(v["event_type"] == "ssh_failed_login" for v in vals),
                "distinct_users_attempted": len({v.get("user") for v in vals if v.get("user")}),
                "distinct_hosts_touched": len({v.get("host") for v in vals if v.get("host")}),
                "bytes_out": sum(int(v.get("bytes", 0)) for v in vals),
            })
        return pd.DataFrame(rows)

    def score(self, events: list[dict]) -> dict[str, float]:
        if self.model is None:
            raise RuntimeError("Anomaly engine unavailable")
        df = self.features(events)
        if df.empty:
            return {}
        x = df[["event_count", "failed_login_count", "distinct_users_attempted", "distinct_hosts_touched", "bytes_out"]]
        raw = -self.model.decision_function(x)
        min_v, max_v = float(raw.min()), float(raw.max())
        if max_v - min_v < 1e-9:
            normalized = np.full(len(raw), 0.5)
        else:
            normalized = (raw - min_v) / (max_v - min_v)
        out = {}
        for (_, row), score in zip(df.iterrows(), normalized):
            out[f"{row['source_ip']}|{row['window']}"] = round(float(score), 4)
        return out
