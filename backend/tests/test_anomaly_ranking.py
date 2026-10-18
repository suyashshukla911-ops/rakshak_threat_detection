import json
from datetime import datetime, timezone
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.detection.anomaly import AnomalyEngine

ROOT = Path(__file__).resolve().parents[2]

def test_isolation_forest_attack_windows_rank_in_top_n():
    engine = AnomalyEngine()
    assert engine.status == "ready"
    assert engine.model is not None

    raw = json.loads((ROOT / "data/sample_logs/ssh_attack.json").read_text(encoding="utf-8"))
    events = []
    for idx, r in enumerate(raw):
        ts = datetime.fromisoformat(r["timestamp"].replace("Z", "+00:00"))
        events.append({**r, "timestamp": ts, "id": f"evt-{idx:05d}"})

    scores = engine.score(events)
    assert len(scores) > 0

    # Sort windows by descending anomaly score
    ranked_windows = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)

    # Attack source IP is 203.0.113.45
    attack_entries = [(k, v) for k, v in ranked_windows if k.startswith("203.0.113.45|")]
    assert len(attack_entries) > 0, "No score windows found for attack source IP"

    # Find rank of top attack window
    top_attack_key, top_attack_score = attack_entries[0]
    top_attack_rank = next(i for i, (k, _) in enumerate(ranked_windows, start=1) if k == top_attack_key)

    # Top attack window must be ranked in top 5 anomalous windows
    assert top_attack_rank <= 5, f"Top attack window {top_attack_key} ranked {top_attack_rank}, expected top 5"
    assert top_attack_score >= 0.70, f"Expected anomaly score >= 0.70, got {top_attack_score}"
