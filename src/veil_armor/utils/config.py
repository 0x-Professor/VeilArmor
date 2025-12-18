"""
Configuration utilities
"""

import configparser
from typing import Dict, Any
from pathlib import Path


def load_config(config_path: str) -> Dict[str, Any]:
    """
    Load configuration from .conf file.
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Configuration dictionary
    """
    if not Path(config_path).exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    parser = configparser.ConfigParser()
    parser.read(config_path)
    
    # Convert to nested dictionary
    config = {}
    for section in parser.sections():
        config[section] = {}
        for key, value in parser.items(section):
            config[section][key] = _parse_value(value)
    
    return config


def _parse_value(value: str) -> Any:
    """
    Parse configuration value to appropriate type.
    
    Args:
        value: String value from config
        
    Returns:
        Parsed value (bool, int, float, list, or str)
    """
    # Boolean
    if value.lower() in ('true', 'yes', 'on'):
        return True
    if value.lower() in ('false', 'no', 'off'):
        return False
    
    # Integer
    try:
        return int(value)
    except ValueError:
        pass
    
    # Float
    try:
        return float(value)
    except ValueError:
        pass
    
    # List (comma-separated or line-separated)
    if '\n' in value:
        return [v.strip() for v in value.split('\n') if v.strip()]
    if ',' in value:
        items = [v.strip() for v in value.split(',') if v.strip()]
        # Try to parse list items
        return [_parse_value(item) for item in items]
    
    # String (strip quotes if present)
    return value.strip('"\'')
