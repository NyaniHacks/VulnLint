import yaml
from pathlib import Path
from typing import Dict, Any

DEFAULT_CONFIG = {
    'excluded_paths': ['tests/', 'venv/', '.venv/'],
    'severity_levels': {
        'CRITICAL': True,
        'HIGH': True,
        'MEDIUM': True,
        'LOW': False,
    },
    'rules': {
        # Will be populated automatically
    }

def load_config(config_path: str = None) -> Dict[str, Any]:
    if config_path and Path(config_path).exists():
        with open(config_path) as f:
            user_onfig = yaml.safe_load(f) or {}
            return {**DEFAULT_CONFIG, **user_config}

    return DEFAULT_CONFIG


}