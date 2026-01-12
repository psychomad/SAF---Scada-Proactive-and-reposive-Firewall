import socket
import time

# SAF Configuration
SAF_IP = "127.0.0.1"
SAF_PORT = 5001

def send_packet(label, data):
    """Utility to send a UDP packet and log the activity"""
    print(f"[*] Sending {label} packet: {data.hex() if isinstance(data, bytes) else data}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(data if isinstance(data, bytes) else data.encode(), (SAF_IP, SAF_PORT))
    sock.close()

# --- TEST 1: AUTHORIZED SENSOR (EXPECTED: ALLOWED) ---
# config.toml has 127.0.0.1 whitelisted as 'centuria' protocol.
# We send a packet starting with 'CE' (0x43, 0x45)
print("\n--- TEST: LEGITTIMATE TRAFFIC ---")
send_packet("VALID_CENTURIA", b"\x43\x45\x01\x02\x03")

time.sleep(1)

# --- TEST 2: AUTHORIZED IP BUT WRONG PROTOCOL (EXPECTED: DPI_REJECT) ---
# We send random binary data from a whitelisted IP. 
# The SAF should inspect the payload and block it because it lacks the 'CE' header.
print("\n--- TEST: DPI VIOLATION ---")
send_packet("INVALID_DATA", b"\x00\x00\x11\x22")

time.sleep(1)

# --- TEST 3: DDOS PROTECTION (EXPECTED: RATE LIMIT & BAN) ---
# This loop sends packets rapidly to trigger the per-IP rate limiter.
print("\n--- TEST: DDOS MITIGATION ---")
for i in range(15):
    send_packet(f"FLOOD_PACKET_{i}", b"\x43\x45\xff\xff")
    # No sleep here to trigger the PPS (Packets Per Second) limit

# --- TEST 4: UNAUTHORIZED IP (EXPECTED: BLOCKED) ---
# Note: To test this properly, run this script from a different machine 
# or remove 127.0.0.1 from the [[sensors]] list in config.toml.
