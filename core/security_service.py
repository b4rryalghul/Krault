"""High-level security operations: login, 2FA, password change."""
import base64
import gc
import hmac
import logging
import secrets
import time
from typing import Optional, Dict, Any, List

import pyotp

from config.constants import SALT_SIZE
from core.security_manager import SecurityManager
from core.database_manager import DatabaseManager
from core.audit_logger import AuditLogger
from models.secure_string import SecureString
from utils.helpers import secure_clear_object


class SecurityService:
    """ Authentication and credential-management operations.
    Feats
    -Master-password verification (with timing-attack protection)
    -Session state (current user, database path, live entries)
    -2FA enable/disable and code verification
    -Master-password change with full database re-encryption
    """

    def __init__(
        self,
        security_manager: SecurityManager,
        database_manager: DatabaseManager,
        audit_logger: AuditLogger,
    ) -> None:
        self.security_manager  = security_manager
        self.database_manager  = database_manager
        self.audit_logger      = audit_logger

        # Session state — populated after a successful login
        self.current_user: Optional[str]       = None
        self.current_database: Optional[str]   = None
        self.entries: List[Dict[str, Any]]     = []
        self._secure_password: SecureString    = SecureString()

    # Login / logout helpers

    def begin_session(
        self,
        username: str,
        password: str,
        database_path: str,
        entries: List[Dict[str, Any]],
    ) -> None:
        """ Store session state after a successful login """
        self.current_user     = username
        self.current_database = database_path
        self.entries          = entries
        self._secure_password.set(password)

    def end_session(self) -> None:
        """Clear all session state on logout or lock."""
        self.current_user     = None
        self.current_database = None
        self.entries          = []
        self._secure_password.clear()
        self.security_manager.invalidate_session()
        gc.collect()

    # Master-password verification
    def verify_master_password(self, username: str, password: str) -> bool:
        """ Verify the master password with timing-attack protection """
        dummy_salt    = None
        temp_security = None
        actual_salt   = None

        try:
            # Always derive a dummy key first — constant timing
            dummy_salt    = secrets.token_bytes(SALT_SIZE)
            temp_security = SecurityManager()
            temp_security.initialize_encryption(
                "dummy_constant_time_password_xyz", "dummy_user", dummy_salt
            )

            profiles    = self.database_manager.load_profiles()
            user_exists = username in profiles

            if user_exists:
                actual_salt = self.database_manager.get_user_salt(username)
                salt_to_use = actual_salt if actual_salt else dummy_salt
                verifier    = profiles[username].get("password_verifier")
            else:
                salt_to_use = dummy_salt
                verifier    = None

            # Candidate key derived from the supplied password
            candidate = SecurityManager()
            candidate.initialize_encryption(password, username, salt_to_use)

            if user_exists and verifier:
                result = candidate.verify_password(verifier)
            else:
                # Dummy verification — same cost, always False
                dummy_verifier = temp_security.create_password_verifier()
                temp_security.verify_password(dummy_verifier)
                result = False

            candidate.invalidate_session()
            return result

        except Exception as e:
            logging.error(f"Password verification error for '{username}': {e}")
            return False

        finally:
            if temp_security:
                temp_security.invalidate_session()
            secure_clear_object(dummy_salt)
            if actual_salt is not None:
                secure_clear_object(actual_salt)
            gc.collect()

    # 2FA
    def verify_2fa_code(self, username: str, code: str) -> bool:
        """ Verify a TOTP code. Returns True if valid """
        profiles     = self.database_manager.load_profiles()
        user_profile = profiles.get(username, {})
        encrypted_secret = user_profile.get("2fa_secret")

        if not encrypted_secret:
            logging.error(f"No 2FA secret found for user '{username}'")
            return False

        try:
            # The secret is stored encrypted; decrypt it with the current session key.
            secret = self.security_manager.decrypt_data(encrypted_secret)
            if not secret:
                logging.error(f"Failed to decrypt 2FA secret for '{username}'")
                return False
            return pyotp.TOTP(secret).verify(code)
        except Exception as e:
            logging.error(f"2FA verification error for '{username}': {e}")
            return False

    def toggle_2fa(self, enable: bool):
        """ Enable or disable 2FA for the current user """
        if not self.current_user:
            return False, "No user is currently logged in"

        try:
            profiles     = self.database_manager.load_profiles()
            user_profile = profiles.get(self.current_user, {})

            if enable and not user_profile.get("2fa_secret"):
                plain_secret = pyotp.random_base32()
                user_profile["2fa_secret"] = self.security_manager.encrypt_data(plain_secret)

            user_profile["2fa_enabled"]  = enable
            profiles[self.current_user]  = user_profile

            if not self.database_manager.save_profiles(profiles):
                return False, "Failed to save 2FA settings"

            event = "2FA_ENABLED" if enable else "2FA_DISABLED"
            self.audit_logger.log_security_event(self.current_user, event, "")
            return True, ""

        except Exception as e:
            logging.error(f"toggle_2fa error: {e}")
            return False, str(e)

    def get_2fa_secret(self) -> Optional[str]:
        """ Return the decrypted TOTP secret for the current user (for QR display) """
        if not self.current_user:
            return None
        profiles = self.database_manager.load_profiles()
        encrypted_secret = profiles.get(self.current_user, {}).get("2fa_secret")
        if not encrypted_secret:
            return None
        try:
            return self.security_manager.decrypt_data(encrypted_secret)
        except Exception as e:
            logging.error(f"Failed to decrypt 2FA secret for {self.current_user}: {e}")
            return None

    # Password change
    def change_master_password(self, new_password: str):
        """ Change the master password with full database re-encryption """
        if not self.current_user or not self.current_database:
            return False, "No active session"

        old_sm   = self.security_manager
        new_salt = self.security_manager.generate_salt()

        try:
            # New key
            new_sm = SecurityManager()
            if not new_sm.initialize_encryption(
                new_password, self.current_user, new_salt
            ):
                return False, "Failed to initialise new encryption key"

            # Decrypt all entries with OLD key
            entries = self.database_manager.load_data(self.current_database)

            # Swap to new key and save and re-encrypts automatically
            self.security_manager                  = new_sm
            self.database_manager.security_manager = new_sm

            if not self.database_manager.save_data(entries, self.current_database):
                self.security_manager                  = old_sm
                self.database_manager.security_manager = old_sm
                return False, "Failed to save re-encrypted database"

            # Persist new salt
            salts                    = self.database_manager.load_salts()
            salts[self.current_user] = base64.b64encode(new_salt).decode()
            if not self.database_manager.save_salts(salts):
                logging.critical("Salt save failed after re-encryption!")
                return False, "Salt update failed — do not close the application"

            # Update password verifier in profile
            new_verifier = new_sm.create_password_verifier()
            profiles     = self.database_manager.load_profiles()
            if self.current_user in profiles:
                profiles[self.current_user]["password_verifier"] = new_verifier
                self.database_manager.save_profiles(profiles)

            # Update session
            self.entries = entries
            self._secure_password.set(new_password)

            self.audit_logger.log_security_event(
                self.current_user, "PASSWORD_CHANGE", "Master password changed"
            )
            old_sm.invalidate_session()
            return True, ""

        except Exception as e:
            logging.error(f"Password change error: {e}")
            self.security_manager                  = old_sm
            self.database_manager.security_manager = old_sm
            return False, str(e)

    # Registration helper
    def register_user(self, username: str, password: str, salt: bytes):
        """ Finalise a new user's profile by storing the password verifier """
        try:
            verifier = self.security_manager.create_password_verifier()
            profiles = self.database_manager.load_profiles()

            if username in profiles:
                return False, f"User '{username}' already exists"

            profiles[username] = {
                "username":          username,
                "2fa_enabled":       False,
                "2fa_secret":        None,
                "password_verifier": verifier,
            }

            if not self.database_manager.save_profiles(profiles):
                return False, "Failed to save user profile"

            self.audit_logger.log_event(
                "REGISTRATION", username, "New user registered", success=True
            )
            return True, ""

        except Exception as e:
            logging.error(f"Registration error for '{username}': {e}")
            return False, str(e)

    # Internal helpers
    def _constant_time_compare(self, a: str, b: str) -> bool:
        """Constant-time string comparison via hmac.compare_digest."""
        try:
            return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
        except Exception:
            return False