import random
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path

SCENARIOS = [
    [61, 62, 63, 64, 65, 66, 67],
    [71, 72, 73, 74, 75, 76, 77, 78],
    [81, 82, 83, 84, 85, 86, 87, 88, 89, 90],
    [91, 92, 93],
    [94, 95, 96, 97],
]

TARGET = "127.0.0.1"
PROJECT_ROOT = Path(__file__).resolve().parents[1]
COLLECTOR = PROJECT_ROOT / "lab" / "collect_nmap.py"

selected = random.choice(SCENARIOS)
scan_id = uuid.uuid4().hex[:10]
sockets = []

print("=" * 60)
print("       SIEM MINI PLATFORM - AUTOMATIC PORT SCAN LAB")
print("=" * 60)
print(f"Random scenario: {selected}")
print(f"Scan ID: {scan_id}")
print(f"Open-port count: {len(selected)}")
print("Expected SIEM result:", "PORT SCAN ALERT" if len(selected) >= 6 else "NO PORT SCAN ALERT")

try:
    print("\nOpening temporary local lab ports...")
    for port in selected:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((TARGET, port))
        s.listen(5)
        sockets.append(s)
        print(f"  OPEN  {TARGET}:{port}")

    print("\nWaiting briefly for listeners to become ready...")
    time.sleep(0.5)

    print("\nRunning Nmap scan of ports 1-100...")
    result = subprocess.run(
        [sys.executable, str(COLLECTOR), "--scan-id", scan_id],
        cwd=str(PROJECT_ROOT),
        text=True
    )

    if result.returncode != 0:
        raise SystemExit("Nmap collector failed. See the output above.")

    print("\nPort-scan test completed. Check SIEM -> Alerts.")
    print("The temporary ports will now be closed.")
finally:
    for s in sockets:
        try:
            s.close()
        except OSError:
            pass
    print("Temporary lab ports closed.")
