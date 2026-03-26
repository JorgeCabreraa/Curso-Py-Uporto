import sqlite3
from datetime import datetime
from typing import Optional

class DatabaseManager:
    """Manages data persistence in SQLite[cite: 67]."""

    def __init__(self, db_path: str = "network_scanner.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row #Esto permite acceder por nombre de columna [cite: 54]
        return conn

    def _init_db(self):
        """Create the tables according to the required data model [cite: 61, 69]."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # Host Table: ID, IP, MAC, hostname, dates [cite: 63]
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS hosts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT UNIQUE NOT NULL,
                    mac_address TEXT,
                    hostname TEXT,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP
                )
            ''')

            #Table scan results [cite: 64, 65]
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id INTEGER,
                    timestamp TIMESTAMP,
                    checked_ports TEXT,
                    open_ports TEXT,
                    FOREIGN KEY (host_id) REFERENCES hosts (id)
                )
            ''')
            conn.commit()

    def add_host(self, ip: str, mac: Optional[str] = None, hostname: Optional[str] = None):
        """Register or update a host[cite: 48, 63]."""
        now = datetime.now().isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # SQL without internal comments to avoid syntax errors
            sql = '''
                INSERT INTO hosts (ip_address, mac_address, hostname, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(ip_address) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    mac_address = COALESCE(excluded.mac_address, hosts.mac_address),
                    hostname = COALESCE(excluded.hostname, hosts.hostname)
            '''
            cursor.execute(sql, (ip, mac, hostname, now, now))
            conn.commit()
    def add_scan_result(self, host_ip: str, checked_ports: list, open_ports: list):
        """Guarda el historial de un escaneo de puertos."""
        now = datetime.now().isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            #Buscamos el ID del host usando su IP
            cursor.execute('SELECT id FROM hosts WHERE ip_address = ?', (host_ip,))
            host_row = cursor.fetchone()

            if host_row:
                host_id = host_row['id'] #Acceso por nombre
                cursor.execute('''
                    INSERT INTO scan_results (host_id, timestamp, checked_ports, open_ports)
                    VALUES (?, ?, ?, ?)
                ''', (host_id, now, str(checked_ports), str (open_ports)))
                conn.commit()

    def get_all_hosts(self):
        """recupera todos los hosts de la base de datos."""
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row #permite acceder al nombre de la columna
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM hosts ORDER BY last_seen DESC')
            return cursor.fetchall()
        
    def get_scan_history(self, host_ip: str):
        """Recupera el historial de escaneos para una IP específica."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            query = '''
                SELECT sr.timestamp, sr.checked_ports, sr.open_ports
                FROM scan_results sr
                JOIN hosts h ON sr.host_id = h.id
                WHERE h.ip_address = ?
                ORDER BY sr.timestamp DESC
            '''
            cursor.execute(query, (host_ip,))
            return cursor.fetchall()