import json
import random
from datetime import datetime, timezone, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data/sample_logs"
DATA.mkdir(parents=True, exist_ok=True)
rng = random.Random(424242)
base = datetime(2026, 10, 18, 9, 0, 0, tzinfo=timezone.utc)
records = []

def add(**kwargs):
    records.append(kwargs)

# 1. Realistic background events (~13,850 events) with realistic mix
users = ["alice", "bob", "carol", "dave", "developer", "analyst"]
hosts = ["server-01", "server-02", "server-03", "server-04"]

# A. Routine system events (~8,000)
for i in range(8000):
    ts = base + timedelta(seconds=rng.randint(0, 3600))
    src = f"10.0.{rng.randint(1,9)}.{rng.randint(2,250)}"
    user = rng.choice(users)
    host = rng.choice(hosts)
    add(
        timestamp=ts.isoformat().replace('+00:00', 'Z'),
        source_ip=src, destination_ip=None, user=user, host=host,
        event_type="other", severity="low", message="Routine kernel and daemon activity",
        bytes=0, process="systemd", path=None
    )

# B. Benign successful logins (~2,500)
for i in range(2500):
    ts = base + timedelta(seconds=rng.randint(0, 3600))
    src = f"10.0.{rng.randint(1,9)}.{rng.randint(2,250)}" if rng.random() > 0.05 else "198.51.100.50"
    user = rng.choice(users)
    host = rng.choice(hosts)
    add(
        timestamp=ts.isoformat().replace('+00:00', 'Z'),
        source_ip=src, destination_ip=None, user=user, host=host,
        event_type="ssh_success_login", severity="low", message=f"Accepted publickey for {user}",
        bytes=0, process="sshd", path=None
    )

# C. Routine benign sudo sessions (~1,200)
sudo_cmds = ["apt update", "systemctl status", "docker ps", "journalctl -n 50", "tail /var/log/nginx/access.log"]
for i in range(1200):
    ts = base + timedelta(seconds=rng.randint(0, 3600))
    src = f"10.0.{rng.randint(1,9)}.{rng.randint(2,250)}"
    user = rng.choice(users)
    host = rng.choice(hosts)
    add(
        timestamp=ts.isoformat().replace('+00:00', 'Z'),
        source_ip=src, destination_ip=None, user=user, host=host,
        event_type="privilege_escalation", severity="low",
        message=f"sudo: {user} : COMMAND={rng.choice(sudo_cmds)}",
        bytes=0, process="sudo", path=None
    )

# D. Benign file accesses (~1,200)
benign_paths = ["/var/log/syslog", "/etc/hosts", "/etc/resolv.conf", "/var/www/html/index.html", "/opt/app/config.json"]
for i in range(1200):
    ts = base + timedelta(seconds=rng.randint(0, 3600))
    user = rng.choice(users)
    host = rng.choice(hosts)
    add(
        timestamp=ts.isoformat().replace('+00:00', 'Z'),
        source_ip=None, destination_ip=None, user=user, host=host,
        event_type="file_access", severity="low", message="File opened for reading",
        bytes=0, process="nginx", path=rng.choice(benign_paths)
    )

# E. Normal small transfers (~800)
for i in range(800):
    ts = base + timedelta(seconds=rng.randint(0, 3600))
    dest = f"10.0.{rng.randint(1,9)}.{rng.randint(2,250)}" if rng.random() > 0.15 else "93.184.216.34"
    user = rng.choice(users)
    host = rng.choice(hosts)
    b = rng.randint(5000, 4 * 1024 * 1024)
    add(
        timestamp=ts.isoformat().replace('+00:00', 'Z'),
        source_ip=None, destination_ip=dest, user=user, host=host,
        event_type="outbound_transfer", severity="low", message="Outbound HTTP/HTTPS request",
        bytes=b, process="curl", path=None
    )

# F. Scattered isolated failed logins (~150, <2 per IP/host window)
for i in range(150):
    ts = base + timedelta(seconds=rng.randint(0, 3600))
    src = f"198.51.100.{rng.randint(100, 200)}"
    user = rng.choice(users)
    host = rng.choice(hosts)
    add(
        timestamp=ts.isoformat().replace('+00:00', 'Z'),
        source_ip=src, destination_ip=None, user=user, host=host,
        event_type="ssh_failed_login", severity="low", message="Failed password (mistype)",
        bytes=0, process="sshd", path=None
    )

# 2. Spec Decoys (must NOT create an incident)
# Decoy 1: 3 failed logins (below 5 threshold)
for i in range(3):
    add(timestamp=(base + timedelta(minutes=10, seconds=i * 20)).isoformat().replace('+00:00', 'Z'),
        source_ip="198.51.100.10", destination_ip=None, user="alice", host="server-01",
        event_type="ssh_failed_login", severity="low", message="Failed password", bytes=0, process="sshd", path=None)

# Decoy 2: 4 mistypes then successful login (below 5 threshold)
for i in range(4):
    add(timestamp=(base + timedelta(minutes=15, seconds=i * 20)).isoformat().replace('+00:00', 'Z'),
        source_ip="198.51.100.11", destination_ip=None, user="bob", host="server-02",
        event_type="ssh_failed_login", severity="low", message="Failed password", bytes=0, process="sshd", path=None)
add(timestamp=(base + timedelta(minutes=16, seconds=50)).isoformat().replace('+00:00', 'Z'),
    source_ip="198.51.100.11", destination_ip=None, user="bob", host="server-02",
    event_type="ssh_success_login", severity="low", message="Accepted password", bytes=0, process="sshd", path=None)

# Decoy 3: internal admin running normal sudo, no preceding brute force
add(timestamp=(base + timedelta(minutes=20)).isoformat().replace('+00:00', 'Z'),
    source_ip="10.0.0.20", destination_ip=None, user="admin", host="server-02",
    event_type="privilege_escalation", severity="low", message="sudo session", bytes=0, process="sudo", path=None)

# Decoy 4: nightly 2 GB backup to internal backup server (allowlisted destination 10.0.0.10)
add(timestamp=(base + timedelta(minutes=25)).isoformat().replace('+00:00', 'Z'),
    source_ip="10.0.0.30", destination_ip="10.0.0.10", user="backup", host="server-03",
    event_type="outbound_transfer", severity="low", message="Nightly backup", bytes=2 * 1024 * 1024 * 1024, process="backupd", path=None)

# 3. Near-miss Decoys (proves exact boundary tests & pivot logic)
# Near-miss 1: admin sudo on server-01 BEFORE attack login occurs (at 09:12Z; attack login is at 09:43Z)
add(timestamp=(base + timedelta(minutes=12)).isoformat().replace('+00:00', 'Z'),
    source_ip="10.0.0.25", destination_ip=None, user="admin", host="server-01",
    event_type="privilege_escalation", severity="low", message="Pre-attack admin maintenance sudo", bytes=0, process="sudo", path=None)

# Near-miss 2: A login from the attack IP 203.0.113.45 more than 10 minutes after the brute force
# (brute force ended at 09:42:34; this login at 10:00:00 is >17 minutes later, exceeding the 600s window)
add(timestamp=(base + timedelta(minutes=60)).isoformat().replace('+00:00', 'Z'),
    source_ip="203.0.113.45", destination_ip=None, user="developer", host="server-01",
    event_type="ssh_success_login", severity="low", message="Late login from attack IP outside 10m window", bytes=0, process="sshd", path=None)


# Near-miss 3a: 4 failures in a 120s window (boundary: 4 vs 5)
for i in range(4):
    add(timestamp=(base + timedelta(minutes=22, seconds=i * 25)).isoformat().replace('+00:00', 'Z'),
        source_ip="198.51.100.33", destination_ip=None, user="dave", host="server-01",
        event_type="ssh_failed_login", severity="low", message="Failed password (4 attempts in 120s)", bytes=0, process="sshd", path=None)

# Near-miss 3b: 5 failures spread over 121s (boundary: 119 vs 121s)
# Times: 0s, 30s, 60s, 90s, 121s -> no 5 failures within <= 120s
for sec in [0, 30, 60, 90, 121]:
    add(timestamp=(base + timedelta(minutes=26, seconds=sec)).isoformat().replace('+00:00', 'Z'),
        source_ip="198.51.100.34", destination_ip=None, user="dave", host="server-01",
        event_type="ssh_failed_login", severity="low", message="Failed password (5 attempts in 121s)", bytes=0, process="sshd", path=None)

# Near-miss 4: 49 MB transfer to external destination (boundary: 49 MB vs 51 MB)
add(timestamp=(base + timedelta(minutes=30)).isoformat().replace('+00:00', 'Z'),
    source_ip="10.0.0.15", destination_ip="198.51.100.77", user="alice", host="server-01",
    event_type="outbound_transfer", severity="low", message="File sync below threshold",
    bytes=49 * 1024 * 1024, process="rsync", path=None)

# 4. Attack chain on exact host/user/IP
atk = "203.0.113.45"
host = "server-01"
user = "admin"
attack_base = base + timedelta(minutes=41)

# 27 failed SSH logins in 94 seconds
for i in range(27):
    add(timestamp=(attack_base + timedelta(seconds=round(i * 94 / 26, 2))).isoformat().replace('+00:00', 'Z'),
        source_ip=atk, destination_ip=None, user=user, host=host,
        event_type="ssh_failed_login", severity="low", message="Failed password for admin", bytes=0, process="sshd", path=None)

# Successful login at 09:43
add(timestamp=(base + timedelta(minutes=43)).isoformat().replace('+00:00', 'Z'),
    source_ip=atk, destination_ip=None, user=user, host=host,
    event_type="ssh_success_login", severity="medium", message="Accepted password for admin", bytes=0, process="sshd", path=None)

# Sudo to root shell at 09:45
add(timestamp=(base + timedelta(minutes=45)).isoformat().replace('+00:00', 'Z'),
    source_ip=None, destination_ip=None, user=user, host=host,
    event_type="privilege_escalation", severity="high", message="sudo to root shell", bytes=0, process="sudo", path=None)

# Sensitive file accesses at 09:47
add(timestamp=(base + timedelta(minutes=47)).isoformat().replace('+00:00', 'Z'),
    source_ip=None, destination_ip=None, user=user, host=host,
    event_type="file_access", severity="high", message="Sensitive file accessed", bytes=0, process="cat", path="/etc/shadow")
add(timestamp=(base + timedelta(minutes=47, seconds=30)).isoformat().replace('+00:00', 'Z'),
    source_ip=None, destination_ip=None, user=user, host=host,
    event_type="file_access", severity="high", message="Database dump accessed", bytes=0, process="cp", path="/var/backups/db.sql")

# Exfiltration at 09:49 (1.8 GB to attacker IP)
add(timestamp=(base + timedelta(minutes=49)).isoformat().replace('+00:00', 'Z'),
    source_ip=None, destination_ip=atk, user=user, host=host,
    event_type="outbound_transfer", severity="critical", message="Large outbound transfer", bytes=int(1.8 * 1024 * 1024 * 1024), process="scp", path=None)

# Stable order, deterministic IDs assigned later by normalizer
records.sort(key=lambda x: x["timestamp"])
normal = [r for r in records if r.get("source_ip") != atk and r.get("bytes", 0) < 100 * 1024 * 1024]
(DATA / "normal_activity.json").write_text(json.dumps(normal, indent=2), encoding="utf-8")
print(f"generated {len(records)} records; {len(normal)} normal records")

