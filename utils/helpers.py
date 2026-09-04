"""Utility functions and helpers"""
import ctypes
import gc
import json
import logging
import os
import secrets
import sys
import time
from typing import Any, Optional

from models.secure_string import SecureString

# Import constants with fallback
try:
    from config.constants import DATA_DIR, CONFIG_FILE
except ImportError:
    if os.name == 'nt':
        DATA_DIR = os.path.join(os.environ.get('APPDATA', ''), 'SecurePasswordManager')
    else:
        DATA_DIR = os.path.join(os.path.expanduser("~"), ".secure_password_manager")
    CONFIG_FILE = os.path.join(DATA_DIR, "config.json")


# Data-directory helpers
def _load_custom_data_directory() -> Optional[str]:
    """Load custom data directory from config if specified."""
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                config = json.load(f)
                custom_dir = config.get('custom_data_directory')
                if custom_dir and os.path.exists(custom_dir):
                    return custom_dir
    except Exception as e:
        logging.warning(f"Could not load custom data directory: {e}")
    return None


def get_data_directory() -> str:
    """ Return the active data directory (custom override or platform default) """
    custom_dir = _load_custom_data_directory()
    if custom_dir and os.path.exists(custom_dir):
        return custom_dir
    return DATA_DIR


def set_custom_data_directory(new_path: str) -> bool:
    """ Persist a custom data-directory path to the config file """
    try:
        if not os.path.exists(new_path):
            os.makedirs(new_path, mode=0o700, exist_ok=True)

        config = {
            'custom_data_directory': new_path,
            'migrated_at': time.time(),
        }
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)
        return True
    except Exception as e:
        logging.error(f"Failed to set custom data directory: {e}")
        return False


# Cryptographic helpers
def secure_random_bytes(length: int) -> bytes:
    """ Return *length* cryptographically secure random bytes """
    return secrets.token_bytes(length)


def generate_password(
    length: int = 18,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    symbol_set: str = "!@#$%^&*()-_=+[]{}|;:,.<>?",
    exclude_ambiguous: bool = False,
) -> str:
    """ Generate a cryptographically secure random password """
    import string as _string

    AMBIGUOUS = set("0Ool1I|")

    def _pool(chars: str) -> str:
        if exclude_ambiguous:
            chars = "".join(c for c in chars if c not in AMBIGUOUS)
        return chars

    pools: list = []
    if use_upper:
        pools.append(_pool(_string.ascii_uppercase))
    if use_lower:
        pools.append(_pool(_string.ascii_lowercase))
    if use_digits:
        pools.append(_pool(_string.digits))
    if use_symbols:
        pools.append(_pool(symbol_set))

    pools = [p for p in pools if p]   # drop pools emptied by ambiguous filter

    if not pools:
        raise ValueError("At least one character category must be enabled")

    length = max(len(pools), min(256, length))  # ensure room for mandatory chars
    full_pool = "".join(pools)

    # Guarantee at least one character from each enabled pool
    mandatory = [secrets.choice(p) for p in pools]
    remainder = [secrets.choice(full_pool) for _ in range(length - len(mandatory))]

    combined = mandatory + remainder
    # Fisher-Yates shuffle via secrets for an unbiased permutation
    for i in range(len(combined) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        combined[i], combined[j] = combined[j], combined[i]

    return "".join(combined)


# Memory-clearing helpers
def secure_clear_object(obj: Any) -> None:
    """ Best-effort in-memory zeroing of sensitive objects """
    try:
        if obj is None:
            return

        if isinstance(obj, SecureString):
            obj.clear()

        elif isinstance(obj, bytearray):
            # Mutable — zero in place, then shrink
            for i in range(len(obj)):
                obj[i] = 0
            obj.clear()

        elif isinstance(obj, bytes):
            try:
                buf = (ctypes.c_char * len(obj)).from_buffer_copy(obj)
                ctypes.memset(buf, 0, len(obj))
            except Exception:
                pass  # Accept the limitation, use bytearray for secrets

        elif isinstance(obj, str):
            pass

        elif hasattr(obj, 'clear'):
            try:
                obj.clear()
            except (AttributeError, TypeError, ValueError) as e:
                logging.warning(f"Could not call clear() on object: {e}")

        elif hasattr(obj, '__dict__'):
            for attr_name in list(obj.__dict__.keys()):
                try:
                    attr_value = getattr(obj, attr_name)
                    secure_clear_object(attr_value)
                    if any(
                        kw in attr_name.lower()
                        for kw in ('password', 'key', 'secret', 'token')
                    ):
                        setattr(obj, attr_name, None)
                except (AttributeError, TypeError) as e:
                    logging.debug(f"Could not clear attribute '{attr_name}': {e}")

    except Exception as e:
        logging.error(f"Error in secure_clear_object: {e}")
    finally:
        gc.collect()


# Logging setup
def setup_logging(log_path: str = 'password_manager.log') -> None:
    fmt = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    handlers = [
        logging.FileHandler(log_path, encoding='utf-8'),
        logging.StreamHandler(sys.stdout),
    ]
    logging.basicConfig(level=logging.INFO, format=fmt, handlers=handlers)
    logging.info("Password Manager application started")


# Clipboard helper
def copy_to_clipboard(root, text: str) -> bool:
    """ Copy *text* to the system clipboard via the tkinter root window """
    try:
        root.clipboard_clear()
        root.clipboard_append(text)
        root.update()   # Flush the clipboard to the OS on some platforms
        return True
    except Exception as e:
        logging.error(f"Failed to copy to clipboard: {e}")
        return False