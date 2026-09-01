import argparse
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import requests

TARGET = "127.0.0.1"
PORT_RANGE = "1-100"
COLLECTOR = "http://127.0.0.1:5000/lab/ingest-port"

parser = argparse.ArgumentParser(description="Collect authorized local Nmap open-port events.")
parser.add_argument("--scan-id", default="manual", help="Correlation ID for this scan session")
parser.add_argument("--ports", default=PORT_RANGE, help="Nmap port range")
args = parser.parse_args()

with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
    xml_path = f.name

print(f"Scanning ONLY {TARGET} ports {args.ports}...")
result = subprocess.run(
    ["nmap", "-p", args.ports, "-oX", xml_path, TARGET],
    capture_output=True,
    text=True
)
if result.returncode != 0:
    print(result.stderr)
    raise SystemExit("Nmap failed. Ensure Nmap is installed and available in PATH.")

root = ET.parse(xml_path).getroot()
ports = root.findall(".//port")
open_ports = []
for p in ports:
    state_node = p.find("state")
    state = state_node.get("state") if state_node is not None else "unknown"
    if state == "open":
        open_ports.append(p)

if not open_ports:
    print("No OPEN ports were discovered.")
    raise SystemExit(0)

for p in open_ports:
    payload = {
        "source_ip": TARGET,
        "port": p.get("portid"),
        "protocol": p.get("protocol", "tcp"),
        "state": "open",
        "source": "nmap_authorized_lab",
        "scan_id": args.scan_id,
    }
    r = requests.post(COLLECTOR, json=payload, timeout=3)
    print(f"Port {payload['port']}/{payload['protocol']} [OPEN] -> SIEM HTTP {r.status_code}")

print(f"Collected {len(open_ports)} OPEN port events for scan {args.scan_id}.")
