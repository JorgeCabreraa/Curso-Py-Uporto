import sqlite3
from datetime import datetime
from typing import Optional

class DatabaseManager:
    """Manages data persistence in SQLite[cite: 67]."""

    def __init__(self, db_path: str = "network_scanner.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        """Create the tables according to the required data model[cite: 61, 69]."""
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