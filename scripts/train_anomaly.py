from pathlib import Path
import json
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"backend"))
from sklearn.ensemble import IsolationForest
import pandas as pd
import joblib
from app.detection.anomaly import AnomalyEngine

ROOT=Path(__file__).resolve().parents[1]
records=json.loads((ROOT/"data/sample_logs/normal_activity.json").read_text(encoding="utf-8"))
X=AnomalyEngine.features(records)
features=X[["event_count","failed_login_count","distinct_users_attempted","distinct_hosts_touched","bytes_out"]]
model=IsolationForest(n_estimators=120, contamination=0.03, random_state=424242)
model.fit(features)
out=ROOT/"data/models/isolation_forest.joblib"
out.parent.mkdir(parents=True, exist_ok=True)
joblib.dump(model, out)
print(f"saved {out}")
