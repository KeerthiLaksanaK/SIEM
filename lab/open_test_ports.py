import random
import socket
import time

SCENARIOS = [
    [61, 62, 63, 64, 65, 66, 67],
    [71, 72, 73, 74, 75, 76, 77, 78],
    [81, 82, 83, 84, 85, 86, 87, 88, 89, 90],
    [91, 92, 93],
    [94, 95, 96, 97],
]

selected_ports = random.choice(SCENARIOS)
sockets = []

print("=" * 55)
print("       SIEM PORT-SCAN LAB")
print("=" * 55)
print(f"\nRandom scenario selected: {selected_ports}")
print(f"Number of ports: {len(selected_ports)}")
print("Expected result:", "PORT SCAN ALERT" if len(selected_ports) >= 6 else "NO PORT SCAN ALERT")

for port in selected_ports:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", port))
        s.listen(5)
        sockets.append(s)
        print(f"Listening on 127.0.0.1:{port}")
    except OSError as e:
        print(f"Could not open port {port}: {e}")

print("\nTest lab is running.")
print("Keep this window open while testing Nmap.")
print("Press Ctrl+C to stop the test ports.")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    for s in sockets:
        s.close()
    print("\nTest ports closed.")
