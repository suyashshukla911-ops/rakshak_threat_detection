import json
import random
from datetime import datetime, timezone, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data/sample_logs"
DATA.mkdir(parents=True, exist_ok=True)
rng = random.Random(424242)
base = datetime(2026,10,18,9,0,0,tzinfo=timezone.utc)
records=[]

def add(**kwargs):
    records.append(kwargs)

# 5k background events
users=["alice","bob","carol","dave","admin"]
hosts=["server-01","server-02","server-03"]
for i in range(5000):
    ts=base+timedelta(seconds=rng.randint(0, 3600))
    src=f"10.0.{rng.randint(1,9)}.{rng.randint(2,250)}"
    user=rng.choice(users)
    host=rng.choice(hosts)
    add(timestamp=ts.isoformat().replace('+00:00','Z'), source_ip=src, destination_ip=None, user=user, host=host, event_type="other", severity="low", message="Benign system activity", bytes=0, process="systemd", path=None)

# Decoy 1: 3 failures
for i in range(3):
    add(timestamp=(base+timedelta(minutes=10,seconds=i*20)).isoformat().replace('+00:00','Z'), source_ip="198.51.100.10", destination_ip=None, user="alice", host="server-01", event_type="ssh_failed_login", severity="low", message="Failed password", bytes=0, process="sshd", path=None)
# Decoy 2: 4 mistypes then login
for i in range(4):
    add(timestamp=(base+timedelta(minutes=15,seconds=i*20)).isoformat().replace('+00:00','Z'), source_ip="198.51.100.11", destination_ip=None, user="bob", host="server-02", event_type="ssh_failed_login", severity="low", message="Failed password", bytes=0, process="sshd", path=None)
add(timestamp=(base+timedelta(minutes=16,seconds=50)).isoformat().replace('+00:00','Z'), source_ip="198.51.100.11", destination_ip=None, user="bob", host="server-02", event_type="ssh_success_login", severity="low", message="Accepted password", bytes=0, process="sshd", path=None)
# Decoy 3: normal sudo
add(timestamp=(base+timedelta(minutes=20)).isoformat().replace('+00:00','Z'), source_ip="10.0.0.20", destination_ip=None, user="admin", host="server-02", event_type="privilege_escalation", severity="low", message="sudo session", bytes=0, process="sudo", path=None)
# Decoy 4: internal nightly backup
add(timestamp=(base+timedelta(minutes=25)).isoformat().replace('+00:00','Z'), source_ip="10.0.0.30", destination_ip="10.0.0.10", user="backup", host="server-03", event_type="outbound_transfer", severity="low", message="Nightly backup", bytes=2*1024*1024*1024, process="backupd", path=None)

# Attack chain on exact host/user/IP
atk="203.0.113.45"; host="server-01"; user="admin"
attack_base=base+timedelta(minutes=41)
for i in range(27):
    add(timestamp=(attack_base+timedelta(seconds=round(i*94/26,2))).isoformat().replace('+00:00','Z'), source_ip=atk, destination_ip=None, user=user, host=host, event_type="ssh_failed_login", severity="low", message="Failed password for admin", bytes=0, process="sshd", path=None)
add(timestamp=(base+timedelta(minutes=43)).isoformat().replace('+00:00','Z'), source_ip=atk, destination_ip=None, user=user, host=host, event_type="ssh_success_login", severity="medium", message="Accepted password for admin", bytes=0, process="sshd", path=None)
add(timestamp=(base+timedelta(minutes=45)).isoformat().replace('+00:00','Z'), source_ip=None, destination_ip=None, user=user, host=host, event_type="privilege_escalation", severity="high", message="sudo to root shell", bytes=0, process="sudo", path=None)
add(timestamp=(base+timedelta(minutes=47)).isoformat().replace('+00:00','Z'), source_ip=None, destination_ip=None, user=user, host=host, event_type="file_access", severity="high", message="Sensitive file accessed", bytes=0, process="cat", path="/etc/shadow")
add(timestamp=(base+timedelta(minutes=47,seconds=30)).isoformat().replace('+00:00','Z'), source_ip=None, destination_ip=None, user=user, host=host, event_type="file_access", severity="high", message="Database dump accessed", bytes=0, process="cp", path="/var/backups/db.sql")
add(timestamp=(base+timedelta(minutes=49)).isoformat().replace('+00:00','Z'), source_ip=None, destination_ip=atk, user=user, host=host, event_type="outbound_transfer", severity="critical", message="Large outbound transfer", bytes=int(1.8*1024*1024*1024), process="scp", path=None)

# Stable order, deterministic IDs assigned later by normalizer.
records.sort(key=lambda x: x["timestamp"])
(DATA/"ssh_attack.json").write_text(json.dumps(records, indent=2), encoding="utf-8")
normal=[r for r in records if r["source_ip"] and r["source_ip"].startswith("10.")]
(DATA/"normal_activity.json").write_text(json.dumps(normal, indent=2), encoding="utf-8")
print(f"generated {len(records)} records; {len(normal)} normal records")
