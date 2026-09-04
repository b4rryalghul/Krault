""" macOS-specific helper functions """
import platform
import logging
from typing import Dict, Any

def get_macos_appearance_settings() -> Dict[str, Any]:
    """ Get macOS-specific appearance settings """
    if platform.system() != "Darwin":
        return {'dark_mode': False}
        
    try:
        import subprocess
        # Detect dark mode
        result = subprocess.run([
            'defaults', 'read', '-g', 'AppleInterfaceStyle'
        ], capture_output=True, text=True)
        dark_mode = result.returncode == 0  # Command succeeds if dark mode enabled
        return {'dark_mode': dark_mode}
    except Exception as e:
        logging.debug(f"Could not detect macOS appearance settings: {e}")
        return {'dark_mode': False}

def is_macos_dark_mode() -> bool:
    """ Convenience function to check only dark mode """
    return get_macos_appearance_settings()['dark_mode']