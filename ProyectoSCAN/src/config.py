import yaml
import os

class Config:
    """loads and manages the scanner's configuration from a YAML file."""

    def __init__(self, config_path: str = "config.yaml"):
        #We look for the file in the project's root directory
        self.config_path = config_path
        self.settings = self._load_config()

    def _load_config(self):
        if not os.path.exists(self.config_path):
            #default settings if the file does not exist
            return {
                "network": {"default_range": "192.168.1.0/24", "timeout": 1.0},
                "scanning": {"default_ports": [22, 80, 443, 3389, 8080]},
                "storage": {"db_path": "network_scanner.db"}
            }
        with open (self.config_path, 'r') as file:
            return yaml.safe_load(file)
        
    @property
    def db_path(self) -> str:
        return self.settings['storage']['db_path'] #[cite:82]
    
    @property
    def default_range(self) -> str:
        return self.settings['network']['default_range'] #[cite: 80]
    
    @property
    def default_ports(self) -> list[int]:
        return self.settings['scanning']['default_ports'] #[cite: 81]