import sqlite3
from datetime import datetime
class DatabaseManager:
    '''gestiona la persistencia de datos en SQLite para el escaner de red.'''

    def __init__(self, db_path: str = "network_scanner.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self):
        return sqlite3.connect(self.db_path)
    
    def _init_db(self):
        '''crea las tablas necesarias si no existen.'''
        with self._get_connection() as conn:
            cursor = conn.cursor()
            #tabla de hosts
            cursor.execute('''
            CREATE TABLE IF NOT EXIST hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                mac_address TEXT,
                hostname TEXT,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP
            )
        ''')
        #tabla de resultados de escaneo [cite: 65]
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                       id INTEGER PRIMARY KEY AUTOINCREMENT,
                       host_id INTEGER,
                       time_stamp TIMESTAMP,
                       checkeed_ports TEXT,
                       open_ports TEXT,
                       open_ports TEXT,
                       FOREIGN KEY (host_id) REFERENCES hosts (id)
            )
        ''')
        conn.commit()
    def add_host(self, ip: str, mac: str = none, hostname: str = none):
        '''Registra o actualiza un host descubierto.'''
        now = datetime.now().isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO hosts (ip:address, mac_address, hostname, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?)
                on conflict (IP_ADDRESS) dont update set
                    LAST_SEEN = excluded. last_seen,
                           hostname = COALESCE (excluded.hostname, hosts)
                           )