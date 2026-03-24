import scapy.all as scapy
from typing import List, Dict
import socket

class NetworkScanner:
    """Clase encargada de las operaciones de red: descubrimiento y escaneo de puertos."""

    @staticmethod
    def discover_devices(ip_range: str) -> List[Dict[str, str]]:
        """
        Descubre dispositivos en la red local enviando peticiones ARP.
        :param ip_range: Rango de IP en formato CIDR (ej: 192.168.1.0/24)
        :return: Lista de diccionarios con IP y MAC de los dispositivos encontrados.
        """
        print(f"[*] Iniciando descubrimiento en el rango: {ip_range}...")
        
        # 1. Crear una petición ARP para preguntar '¿Quién tiene esta IP?'
        arp_request = scapy.ARP(pdst=ip_range)

        # 2. Crear un paquete Ethernet de difusión (broadcast) para enviarlo a todos
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

        # 3. Combinar ambos paquetes
        arp_request_broadcast = broadcast / arp_request

        # 4. Enviar el paquete y recibir las respuestas (timeout de 2 seg para no esperar siempre)
        answered_list = scapy.srp(arp_request_broadcast, timeout= 2, verbose= False)[0]
        devices = []

        for element in answered_list:
            device_info = {
                "ip": element[1].psrc,
                "mac": element[1].hwsrc
            }
            devices.append(device_info)
        return devices
    
    @staticmethod
    def scan_ports(ip: str, ports: list[int]) -> list[int]:
        """
        Scan a list of ports on a specific IP address.
        :param ip: IP address to scan.
        :param ports: List of ports (ej: [22, 80, 443]).
        :return: List of open ports.
        """
        open_ports = []
        print(f"[*] Scanning ports for {ip}...")

        for port in ports:
            #create a socket TCP
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                #We set a short timeout so it doesn't take too long
                s.settimeout(0.5)
                #connect_ex return 0 if the connection was successful (port open) [cite: 75]
                result = s.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)

        return open_ports
# Small local test
if __name__ == "__main__":
    # Replace this with your actual rank if it's different
    resultados = NetworkScanner.discover_devices("192.168.1.0/24")
    for dev in resultados:
        print(f"Device found: IP {dev['ip']} - MAC {dev['mac']}")