from flask import Flask, render_template, redirect, url_for
from database import DatabaseManager
from config import Config
from scanner import NetworkScanner # Importamos tu escáner

app = Flask(__name__)
cfg = Config()
db = DatabaseManager(cfg.db_path)
scanner = NetworkScanner()

@app.route('/')
def index():
    # Usamos la nueva función con puertos
    hosts = db.get_hosts_with_ports()
    return render_template('index.html', hosts=hosts)

@app.route('/discover-all')
def run_discovery():
    """Ruta para el botón 'Descubrir + Registrar'"""
    # 1. Descubrir
    devices = scanner.discover_devices(cfg.default_range)
    # 2. Guardar en DB
    for dev in devices:
        db.add_host(dev['ip'], dev['mac'])
    return redirect(url_for('index'))

@app.route('/scan/<ip>')
def run_scan(ip):
    """Ruta para escanear puertos de una IP específica"""
    open_ports = scanner.scan_ports(ip, cfg.default_ports)
    db.add_scan_result(ip, cfg.default_ports, open_ports)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)