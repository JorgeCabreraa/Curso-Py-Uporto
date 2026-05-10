🛡️ CyberScanner: Network Discovery & Port Audit Tool
Una herramienta modular y profesional desarrollada en Python diseñada para el descubrimiento de dispositivos en redes locales y auditoría de servicios mediante escaneo de puertos. Este proyecto combina la potencia de una interfaz de línea de comandos (CLI) con un Dashboard visual moderno basado en la web.

🚀 Características Principales
Descubrimiento de Red (Layer 2): Utiliza paquetes ARP a través de la librería Scapy para identificar IPs y direcciones MAC activas de forma rápida.

Escaneo de Puertos TCP: Implementa un escaneo de tipo TCP Connect para identificar servicios abiertos en hosts específicos.

Base de Datos Relacional: Almacenamiento persistente en SQLite para mantener un inventario de hosts y un historial detallado de cada escaneo realizado.

Interfaz de Comandos (CLI): Herramienta potente que permite anular configuraciones del archivo YAML mediante el uso de flags específicos (ej. --ports).

Dashboard Web: Interfaz visual responsiva diseñada en Dark Mode con Flask y Jinja2 para monitorear y disparar acciones de red con un solo clic.

🏗️ Arquitectura Modular
El proyecto está diseñado siguiendo principios de Separación de Responsabilidades para facilitar su mantenimiento:

config.py: Centraliza la configuración mediante un archivo config.yaml para evitar valores hardcoded.

database.py: Gestiona todo el ciclo de vida de los datos (CRUD) en la base de datos SQLite.

scanner.py: Contiene el "músculo" técnico que interactúa con las capas del modelo OSI.

main.py: Punto de entrada para la administración vía CLI.

web_app.py: Servidor Flask que expone los datos y funcionalidades al navegador.

🛠️ Instalación y Configuración
Clonar el repositorio:

Bash
git clone https://github.com/JorgeCabreraa/Scanner.git
cd ProyectoSCAN
Instalar dependencias:

Bash
pip install scapy flask pyyaml
Configurar el entorno:
Edita el archivo config.yaml para establecer tu rango de red y puertos de interés:

YAML
network:
  default_range: "192.168.1.0/24"
scanning:
  default_ports: [22, 80, 443, 8080]
💻 Uso de la Herramienta
Interfaz de Línea de Comandos (CLI)
La CLI permite ejecutar tareas administrativas con gran flexibilidad:

Descubrimiento: python src/main.py discover

Escaneo de puertos: python src/main.py scan 192.168.1.1 --ports 21,22,80

Listado de hosts: python src/main.py list-hosts

Historial: python src/main.py history 192.168.1.1

Interfaz Web
Inicia el servidor para acceder al Dashboard visual:

Bash
python src/web_app.py
Accede mediante tu navegador a: http://127.0.0.1:5000

🎓 Aprendizajes Técnicos
Durante el desarrollo de este proyecto se han consolidado conceptos avanzados de:

Programación Asíncrona: Manejo de procesos de red que requieren tiempos de espera (timeouts).

SQL Avanzado: Uso de relaciones entre tablas y consultas JOIN para visualización de historial.

Seguridad de Red: Comprensión de protocolos ARP y el "handshake" de TCP.

UI/UX en Seguridad: Diseño de interfaces minimalistas y funcionales para el análisis de datos críticos.

⚖️ Descargo de Responsabilidad (Ethical Disclaimer)
Esta herramienta ha sido creada con fines educativos y de auditoría ética. El autor no se hace responsable del uso indebido de esta aplicación. Realizar escaneos en redes o dispositivos sin autorización previa es ilegal.

Desarrollado por: Jorge Cabrera
