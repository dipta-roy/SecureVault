import os
from typing import List, Optional
from . import config

def get_recent_vault_paths() -> List[str]:
    """
    Loads the list of recent vault paths from the configuration file.
    Filters out paths that no longer exist.
    """
    config_dir = os.path.join(os.path.expanduser("~"), config.CONFIG_DIR_NAME)
    recent_file = os.path.join(config_dir, config.RECENT_VAULTS_FILE)

    recent_paths = []
    if os.path.exists(recent_file):
        with open(recent_file, 'r') as f:
            for line in f:
                path = line.strip()
                if path and os.path.exists(path):
                    recent_paths.append(path)
    return recent_paths

def save_recent_vault_path(path: str):
    """
    Saves a vault path to the list of recent vaults.
    Ensures uniqueness and keeps the list limited to the last 10.
    """
    config_dir = os.path.join(os.path.expanduser("~"), config.CONFIG_DIR_NAME)
    os.makedirs(config_dir, exist_ok=True)
    recent_file = os.path.join(config_dir, config.RECENT_VAULTS_FILE)

    recent = get_recent_vault_paths() # Get current valid recent paths

    # Add new path at beginning, ensuring uniqueness
    if path in recent:
        recent.remove(path)
    recent.insert(0, path)

    # Keep only last 10
    recent = recent[:config.MAX_RECENT_VAULTS]

    # Write back
    with open(recent_file, 'w') as f:
        for p in recent:
            f.write(p + '\n')
