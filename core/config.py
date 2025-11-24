"""
Configuration management for Domain ASN Mapper.

This module handles loading configuration from:
1. Default values
2. YAML config file
3. Environment variables (highest priority)
"""

import os
import yaml
import logging
from typing import Dict, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class Config:
    """Configuration management class."""

    # Default configuration values
    DEFAULTS = {
        'dns': {
            'timeout': 5,
            'retries': 2,
            'nameservers': None,  # None means use system default
        },
        'processing': {
            'max_workers': 10,
            'batch_size': 100,
            'progress_update_interval': 100,
        },
        'output': {
            'default_format': 'json',
            'create_directories': True,
        },
        'logging': {
            'level': 'INFO',
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            'file': None,  # None means log to console only
            'json_format': False,  # Set to True for JSON structured logging
            'max_bytes': 10485760,  # 10MB
            'backup_count': 5,
        },
        'web': {
            'host': '0.0.0.0',
            'port': 5000,
            'debug': False,
            'max_upload_size': 52428800,  # 50MB
            'session_secret': None,  # Must be set via env var in production
        },
        'mrt': {
            'cache_dir': None,  # None means use temp dir
            'auto_download': False,
            'default_url': None,
        }
    }

    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize configuration.

        Args:
            config_file: Path to YAML config file (optional)
        """
        self._config = self._load_config(config_file)

    def _load_config(self, config_file: Optional[str] = None) -> Dict[str, Any]:
        """
        Load configuration from file and environment variables.

        Priority (highest to lowest):
        1. Environment variables
        2. Config file
        3. Defaults

        Args:
            config_file: Path to config file

        Returns:
            Merged configuration dictionary
        """
        # Start with defaults
        config = self._deep_copy(self.DEFAULTS)

        # Load from config file if provided
        if config_file:
            file_config = self._load_from_file(config_file)
            if file_config:
                config = self._deep_merge(config, file_config)

        # Override with environment variables
        config = self._load_from_env(config)

        return config

    def _load_from_file(self, config_file: str) -> Optional[Dict[str, Any]]:
        """
        Load configuration from YAML file.

        Args:
            config_file: Path to YAML file

        Returns:
            Configuration dictionary or None if file doesn't exist
        """
        config_path = Path(config_file)

        if not config_path.exists():
            logger.warning(f"Config file not found: {config_file}")
            return None

        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)

            logger.info(f"Loaded configuration from {config_file}")
            return config or {}
        except Exception as e:
            logger.error(f"Error loading config file {config_file}: {e}")
            return None

    def _load_from_env(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Override configuration with environment variables.

        Environment variables use the pattern: DOMAIN_ASN_<SECTION>_<KEY>
        Example: DOMAIN_ASN_DNS_TIMEOUT=10

        Args:
            config: Current configuration dictionary

        Returns:
            Updated configuration dictionary
        """
        env_prefix = 'DOMAIN_ASN_'

        # DNS settings
        if os.getenv(f'{env_prefix}DNS_TIMEOUT'):
            config['dns']['timeout'] = int(os.getenv(f'{env_prefix}DNS_TIMEOUT'))

        if os.getenv(f'{env_prefix}DNS_RETRIES'):
            config['dns']['retries'] = int(os.getenv(f'{env_prefix}DNS_RETRIES'))

        # Processing settings
        if os.getenv(f'{env_prefix}MAX_WORKERS'):
            config['processing']['max_workers'] = int(os.getenv(f'{env_prefix}MAX_WORKERS'))

        # Logging settings
        if os.getenv(f'{env_prefix}LOG_LEVEL'):
            config['logging']['level'] = os.getenv(f'{env_prefix}LOG_LEVEL')

        if os.getenv(f'{env_prefix}LOG_FILE'):
            config['logging']['file'] = os.getenv(f'{env_prefix}LOG_FILE')

        if os.getenv(f'{env_prefix}LOG_JSON'):
            config['logging']['json_format'] = os.getenv(f'{env_prefix}LOG_JSON').lower() == 'true'

        # Web settings
        if os.getenv(f'{env_prefix}WEB_HOST'):
            config['web']['host'] = os.getenv(f'{env_prefix}WEB_HOST')

        if os.getenv(f'{env_prefix}WEB_PORT'):
            config['web']['port'] = int(os.getenv(f'{env_prefix}WEB_PORT'))

        if os.getenv(f'{env_prefix}WEB_DEBUG'):
            config['web']['debug'] = os.getenv(f'{env_prefix}WEB_DEBUG').lower() == 'true'

        if os.getenv('SESSION_SECRET'):
            config['web']['session_secret'] = os.getenv('SESSION_SECRET')

        # MRT settings
        if os.getenv(f'{env_prefix}MRT_CACHE_DIR'):
            config['mrt']['cache_dir'] = os.getenv(f'{env_prefix}MRT_CACHE_DIR')

        if os.getenv(f'{env_prefix}MRT_AUTO_DOWNLOAD'):
            config['mrt']['auto_download'] = os.getenv(f'{env_prefix}MRT_AUTO_DOWNLOAD').lower() == 'true'

        return config

    def _deep_copy(self, obj: Any) -> Any:
        """Deep copy a nested dictionary."""
        if isinstance(obj, dict):
            return {k: self._deep_copy(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._deep_copy(item) for item in obj]
        else:
            return obj

    def _deep_merge(self, base: Dict, override: Dict) -> Dict:
        """
        Deep merge two dictionaries.

        Args:
            base: Base dictionary
            override: Dictionary with override values

        Returns:
            Merged dictionary
        """
        result = self._deep_copy(base)

        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = self._deep_copy(value)

        return result

    def get(self, section: str, key: str, default: Any = None) -> Any:
        """
        Get a configuration value.

        Args:
            section: Configuration section (e.g., 'dns', 'processing')
            key: Configuration key within section
            default: Default value if not found

        Returns:
            Configuration value
        """
        try:
            return self._config.get(section, {}).get(key, default)
        except (KeyError, AttributeError):
            return default

    def get_section(self, section: str) -> Dict[str, Any]:
        """
        Get an entire configuration section.

        Args:
            section: Configuration section name

        Returns:
            Section dictionary
        """
        return self._config.get(section, {})

    def set(self, section: str, key: str, value: Any) -> None:
        """
        Set a configuration value.

        Args:
            section: Configuration section
            key: Configuration key
            value: Value to set
        """
        if section not in self._config:
            self._config[section] = {}

        self._config[section][key] = value

    def to_dict(self) -> Dict[str, Any]:
        """
        Get the complete configuration as a dictionary.

        Returns:
            Configuration dictionary
        """
        return self._deep_copy(self._config)

    def save_to_file(self, config_file: str) -> None:
        """
        Save current configuration to a YAML file.

        Args:
            config_file: Path to save configuration
        """
        config_path = Path(config_file)
        config_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            with open(config_path, 'w') as f:
                yaml.dump(self._config, f, default_flow_style=False, sort_keys=False)

            logger.info(f"Configuration saved to {config_file}")
        except Exception as e:
            logger.error(f"Error saving config file {config_file}: {e}")
            raise


# Global configuration instance
_global_config: Optional[Config] = None


def get_config(config_file: Optional[str] = None) -> Config:
    """
    Get the global configuration instance.

    Args:
        config_file: Path to config file (only used on first call)

    Returns:
        Configuration instance
    """
    global _global_config

    if _global_config is None:
        # Look for config.yaml in current directory or project root
        default_config_paths = [
            'config.yaml',
            'config.yml',
            os.path.expanduser('~/.domain-asn-mapper/config.yaml'),
        ]

        config_path = config_file
        if not config_path:
            for path in default_config_paths:
                if os.path.exists(path):
                    config_path = path
                    break

        _global_config = Config(config_path)

    return _global_config


def reset_config() -> None:
    """Reset the global configuration instance (mainly for testing)."""
    global _global_config
    _global_config = None
