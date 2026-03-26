import argparse
import sys
import os

# Asegurar que encuentre los módulos locales
sys.path.append(os.path.dirname(__file__))

from scanner import NetworkScanner
from database import DatabaseManager
from config import Config

def cmd_discover(args, cfg, db):
    """Lógica para el comando 'discover'"""
    target = args.range or cfg.default_range
    print(f"[*] Searching for devices on: {target}...")
    found = NetworkScanner.discover_devices(target)
    
    for dev in found:
        db.add_host(ip=dev['ip'], mac=dev.get('mac'))
        print(f"[+] Host detected: {dev['ip']} ({dev.get('mac', 'N/A')})")
    print(f"\n[!] Summary: {len(found)} identified hosts.") #[cite: 88]

def cmd_scan(args, cfg, db):
    """Lógica para el comando 'scan'"""
    ports = cfg.default_ports
    print(f"[*] Scanning common ports on: {args.ip}...")
    open_ports = NetworkScanner.scan_ports(args.ip, ports)
    
    # Guardar resultado en DB
    db.add_scan_result(args.ip, ports, open_ports)
    
    if open_ports:
        print(f"[+] Open ports on {args.ip}: {open_ports}")
    else:
        print(f"[-] No open ports were found on {args.ip}.") #[cite: 87]

def main():
    cfg = Config()
    db = DatabaseManager(cfg.db_path)
    
    # Configuramos argparse para manejar subcomandos 
    parser = argparse.ArgumentParser(description="CyberScanner CLI - Network Audit Tool")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Subcomando: discover [cite: 45]
    desc_parser = subparsers.add_parser("discover", help="Discover devices on the network")
    desc_parser.add_argument("--range", help="Rango CIDR (ej: 192.168.1.0/24)")

    # Subcomando: scan [cite: 49]
    scan_parser = subparsers.add_parser("scan", help="Scan a host's ports")
    scan_parser.add_argument("ip", help="IP address of the host to be scanned")
    # Subcomando: list-hosts
    subparsers.add_parser("list-hosts", help="Show all known hosts")

    history_parser = subparsers.add_parser("history", help="View scan history for an IP address")
    history_parser.add_argument("ip", help="IP from the host to be queried")
                                           

    args = parser.parse_args()

    # Ejecución según el comando ingresado
    if args.command == "discover":
        cmd_discover(args, cfg, db)
    elif args.command == "scan":
        cmd_scan(args, cfg, db)
    elif args.command == "list-hosts":
        cmd_list(args, cfg, db)
    elif args.command == "history":
        cmd_history(args,cfg ,db)
    else:
        parser.print_help()
    

def cmd_list(args, cfg, db):
    """Logic for the ‘list-hosts’ command'"""
    hosts = db.get_all_hosts()
    if not hosts:
        print("[!] There are no hosts registered in the database.")
        return

    print(f"{'IP':<15} | {'MAC':<17} | {'Last seen':<20}")
    print("-" * 55)
    for h in hosts:
        print(f"{h['ip_address']:<15} | {h['mac_address'] or 'N/A':<17} | {h['last_seen'][:19]}")

def cmd_history(args, cfg, db):
    """Lógica para el comando 'history'"""
    print(f"[*] Consultando historial para: {args.ip}...")
    history = db.get_scan_history(args.ip)
    
    if not history:
        print(f"[!] No hay registros de escaneos para la IP: {args.ip}")
        return

    print(f"\n{'Fecha y Hora':<20} | {'Puertos Abiertos'}")
    print("-" * 50)
    for row in history:
        # Formateamos la fecha para que se vea limpia
        date_str = row['timestamp'][:19].replace('T', ' ')
        print(f"{date_str:<20} | {row['open_ports']}")

if __name__ == "__main__":
    main()
