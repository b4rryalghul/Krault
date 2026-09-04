"""Application constants and configuration"""
import os

# Security Constants
LOCK_TIMEOUT = 300
MAX_ENTRIES = 1000
MAX_LOGIN_ATTEMPTS = 5
ACCOUNT_LOCKOUT_TIME = 1800
SALT_SIZE = 32
SESSION_TIMEOUT = 3600

# Key derivation function used for all accounts
KDF_DEFAULT         = "argon2id"

# Argon2id parameters — OWASP-recommended baseline for an interactive
ARGON2_TIME_COST    = 3            # iterations
ARGON2_MEMORY_COST  = 65536        # KiB (64 MiB)
ARGON2_PARALLELISM  = 4            # lanes
ARGON2_HASH_LEN     = 32           # 256-bit derived key

# Clipboard 
# Seconds after copying a password/secret before the clipboard is automatically cleared
CLIPBOARD_CLEAR_SECONDS = 25

# 2FA
TOTP_VALID_WINDOW = 1

# Data directories
if os.name == 'nt':
    DATA_DIR = os.path.join(os.environ.get('APPDATA', ''), 'SecurePasswordManager')
else:
    DATA_DIR = os.path.join(os.path.expanduser("~"), ".secure_password_manager")

BACKUP_DIR = os.path.join(DATA_DIR, "backups")
LOGS_DIR = os.path.join(DATA_DIR, "logs")
CONFIG_FILE = os.path.join(DATA_DIR, "config.json")

# Persisted brute-force tracking (survives app restarts) and TOTP replay tracking (last accepted time-step per user).
LOGIN_ATTEMPTS_FILE = os.path.join(DATA_DIR, "login_attempts.json")
TOTP_STATE_FILE     = os.path.join(DATA_DIR, "totp_state.json")

# Password Policy
DEFAULT_PASSWORD_POLICY = {
    'min_length': 8,
    'require_uppercase': True,
    'require_lowercase': True,
    'require_digits': True,
    'require_special': True,
    'min_strength': 3
}

# Add this to config/constants.py
THEME_CONFIG_FILE = os.path.join(DATA_DIR, "theme_config.json")

