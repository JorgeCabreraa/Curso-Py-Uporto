import sys
import os

# Ensure that Python can find the local modules in the 'src' folder
sys.path.append(os.path.dirname(__file__))

from scanner import NetworkScanner
from database import DatabaseManager
from config import Config

def run_discovery():
    """Perform configuration-based discovery[cite: 45, 80]."""
    cfg = Config()
    db = DatabaseManager(cfg.db_path)
    
    print(f"[*] Beginning the discovery phase in: {cfg.default_range}")
    # Discovery via ARP or ping sweep [cite: 47, 73]
    found_devices = NetworkScanner.discover_devices(cfg.default_range)

    for device in found_devices:
        db.add_host(ip=device['ip'], mac=device.get('mac'))
        print(f"[+] Registered device: {device['ip']}")

    print(f"\n[!] Task completed: {len(found_devices)} hosts identificados[cite: 88].")

if __name__ == "__main__":
    run_discovery()