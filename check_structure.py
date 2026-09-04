"""Verify all required project files are present before launching."""
import os
import sys

required_files = [
    # Entry points
    'main.py',
    'run.py',

    # Config
    'config/__init__.py',
    'config/constants.py',
    'config/themes.py',

    # Core — all six modules must be present
    'core/__init__.py',
    'core/security_manager.py',
    'core/security_service.py',
    'core/session_manager.py',
    'core/database_manager.py',
    'core/password_policy.py',
    'core/audit_logger.py',

    # UI
    'ui/__init__.py',
    'ui/screens.py',

    # Models
    'models/__init__.py',
    'models/secure_string.py',

    # Utils
    'utils/__init__.py',
    'utils/helpers.py',
    'utils/macos_helper.py',

    # Build / packaging
    'requirements.txt',
]

def check_structure(base_dir: str = '.') -> bool:
    print(f"Checking project structure in: {os.path.abspath(base_dir)}\n")
    missing = []
    for f in required_files:
        path = os.path.join(base_dir, f)
        if os.path.exists(path):
            print(f"  ✓  {f}")
        else:
            print(f"  ✗  {f}  ← MISSING")
            missing.append(f)

    print()
    if missing:
        print(f"ERROR: {len(missing)} required file(s) missing — fix before running.")
        return False
    else:
        print("All required files present.")
        return True

if __name__ == "__main__":
    ok = check_structure()
    sys.exit(0 if ok else 1)