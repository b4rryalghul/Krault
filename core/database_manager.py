"""Manages database operations and integrity"""
import os
import json
import base64
import logging
import hashlib
import hmac
import shutil
import platform
from typing import Optional, Dict, List, Any, Tuple
import secrets
from pathlib import Path


from utils.macos_helper import get_macos_appearance_settings
from config.constants import DATA_DIR, BACKUP_DIR, LOGS_DIR
from utils.helpers import get_data_directory

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
    
    class MacOSFileMonitor(FileSystemEventHandler):
        """ Monitor file changes on macOS """
        
        def __init__(self, database_manager):
            self.db_manager = database_manager
            
        def on_modified(self, event):
            if event.src_path.endswith('.db'):
                logging.info(f"Database file modified: {event.src_path}")
                # Trigger integrity check
                integrity_ok, message = self.db_manager.verify_database_integrity(event.src_path)
                if not integrity_ok:
                    logging.warning(f"Integrity check failed after modification: {message}")

except ImportError:
    HAS_WATCHDOG = False
    
    # Define a dummy class when watchdog is not available
    class MacOSFileMonitor:
        """ Dummy class when watchdog is not available """
        def __init__(self, database_manager):
            pass
        def on_modified(self, event):
            pass


class DatabaseManager:
    """ Manages database operations including storage, retrieval, and integrity verification.
    Security Features:
    -Secure directory creation with proper permissions
    -Data integrity verification with checksums
    -Path sanitization to prevent directory traversal
    -Secure file handling
    -Automatic database creation for new users """
    
    def __init__(self, security_manager: 'SecurityManager'):
        """ Initialize DatabaseManager with proper data directory structure """
        self.security_manager = security_manager
        self.data_dir = self.get_macos_data_directory()
        self.backup_dir = os.path.join(self.data_dir, "backups")
        self.logs_dir = os.path.join(self.data_dir, "logs")

        # Define file paths for user data
        self.salt_file = os.path.join(self.data_dir, "salts.json")  # User encryption salts
        self.profiles_file = os.path.join(self.data_dir, "profiles.json")  # User profiles
        self.checksum_file = os.path.join(self.data_dir, "database_checksums.json")  # Integrity checks
        self.login_attempts_file = os.path.join(self.data_dir, "login_attempts.json")  # Persisted brute-force tracking
        self.totp_state_file = os.path.join(self.data_dir, "totp_state.json")  # Last-accepted TOTP step per user
        
         # Handle macOS sandbox
        if platform.system() == "Darwin":
            self._handle_macos_sandbox()

        # Create directories if they don't exist
        self._ensure_directories()

        # Setup macOS file monitoring AFTER directories are created
        if platform.system() == "Darwin":
            self.setup_macos_file_monitoring()


    def get_macos_app_support_path(self) -> str:
        """ Get macOS Application Support directory """
        home = Path.home()
        app_support = home / "Library" / "Application Support" / "SecurePasswordManager"
        return str(app_support)

    def get_macos_data_directory(self) -> str:
        """ Get appropriate data directory for macOS """
        if platform.system() == "Darwin":  # macOS
            # Use Application Support for better macOS integration
            app_support_dir = self.get_macos_app_support_path()
            
            # Fallback to current directory if Application Support not accessible
            try:
                Path(app_support_dir).mkdir(parents=True, exist_ok=True, mode=0o700)
                return app_support_dir
            except (PermissionError, OSError):
                logging.warning("Cannot access Application Support, using user directory")
                return str(Path.home() / ".secure_password_manager")
        else:
            from utils.helpers import get_data_directory
            return get_data_directory()

    def _handle_macos_sandbox(self) -> bool:
        """ Check if running in macOS sandbox and adjust paths """
        if platform.system() != "Darwin":
            return False
            
        # Check for sandbox environment variables
        sandboxed = any(var in os.environ for var in [
            'APP_SANDBOX_CONTAINER_ID',
            'SANDBOX_EXECUTABLE_PATH'
        ])
        
        if sandboxed:
            logging.info("Running in macOS sandbox environment")
            # In sandbox, use container-appropriate paths
            container_home = os.environ.get('HOME', '')
            if container_home and container_home.startswith('/Users/'):
                # In an app sandbox, use sandbox-specific paths
                self.data_dir = os.path.join(container_home, "Library", "Application Support", "SecurePasswordManager")
                return True
        
        return False

    def setup_macos_file_monitoring(self):
        """ Setup file system monitoring on macOS """
        if platform.system() == "Darwin" and HAS_WATCHDOG:
            try:
                self.observer = Observer()
                event_handler = MacOSFileMonitor(self)
                self.observer.schedule(event_handler, self.data_dir, recursive=True)
                self.observer.start()
                logging.info("macOS file system monitoring enabled")
            except Exception as e:
                logging.warning(f"Could not enable file system monitoring: {e}")

    def close(self):
        """ Clean up resources, stop file monitoring """
        if hasattr(self, 'observer') and self.observer:
            self.observer.stop()
            self.observer.join()
            logging.info("macOS file monitoring stopped")

    # Add destructor for automatic cleanup
    def __del__(self):
        """ Auto-cleanup when object is destroyed """
        if hasattr(self, 'observer') and self.observer:
            try:
                self.observer.stop()
                self.observer.join(timeout=1.0)
            except Exception:
                pass  # Ignore errors during destruction

    def get_macos_backup_locations(self) -> List[str]:
        """ Get appropriate backup locations for macOS """
        locations = []
        home = Path.home()
        
        # Application Support backups
        locations.append(str(home / "Library" / "Application Support" / "SecurePasswordManager" / "backups"))
        
        # User's Documents folder (if accessible)
        documents_backup = str(home / "Documents" / "SecurePasswordManager_Backups")
        try:
            Path(documents_backup).mkdir(parents=True, exist_ok=True, mode=0o700)
            locations.append(documents_backup)
        except PermissionError:
            pass
        
        # iCloud Drive if available
        icloud_drive = home / "Library" / "Mobile Documents" / "com~apple~CloudDocs"
        if icloud_drive.exists():
            icloud_backup = str(icloud_drive / "SecurePasswordManager_Backups")
            try:
                Path(icloud_backup).mkdir(parents=True, exist_ok=True, mode=0o700)
                locations.append(icloud_backup)
            except PermissionError:
                pass
        
        return locations

    def handle_macos_permission_error(self, operation: str, path: str, error: Exception) -> bool:
        """ Handle macOS-specific permission errors """
        if platform.system() != "Darwin":
            return False
            
        error_msg = str(error).lower()
        
        # Handle common macOS permission issues
        if "operation not permitted" in error_msg:
            logging.warning(f"macOS System Integrity Protection may be blocking {operation}")
            return True
            
        elif "user canceled" in error_msg:
            logging.info("User canceled operation via macOS security prompt")
            return True
            
        elif "couldn't be completed" in error_msg and "permission" in error_msg:
            logging.error(f"macOS permission denied for {operation} at {path}")
            return True
            
        return False

    def _create_secure_directory_macos(self, directory_path: str) -> None:
        """ Create a directory on macOS with Application Support conventions, pathlib for cleaner path handling and respects macOS sandbox rules """
        try:
            path = Path(directory_path)
            if path.exists():
                if not self._is_directory_secure(directory_path):
                    raise RuntimeError(
                        f"Existing directory {directory_path} has insecure permissions"
                    )
                logging.info(f"Using existing secure directory: {directory_path}")
                return

            path.mkdir(parents=True, mode=0o700, exist_ok=False)
            os.chmod(directory_path, 0o700)

            if not self._is_directory_secure(directory_path):
                raise RuntimeError(
                    f"Failed to set secure permissions on macOS for: {directory_path}"
                )

            logging.debug(f"Created secure macOS directory: {directory_path}")

        except FileExistsError:
            if not self._is_directory_secure(directory_path):
                raise RuntimeError(
                    f"macOS directory created by another process has insecure permissions: {directory_path}"
                )
        except Exception as e:
            self.handle_macos_permission_error("create_directory", directory_path, e)
            logging.error(f"Failed to create secure macOS directory {directory_path}: {e}")
            raise


    def _ensure_directories(self) -> None:
        """ Create necessary directories with secure permissions and proper error handling        
        Security Features:
            -Secure directory creation with owner-only permissions (0o700)
            -No fallback to insecure temporary directories
            -Comprehensive permission validation
            -Proper error handling with user feedback
            -Directory integrity checks """
        directories_to_create = [
            self.data_dir,
            self.backup_dir, 
            self.logs_dir
        ]
        
        created_dirs = []
        
        try:
            for directory in directories_to_create:
                try:
                    self._create_secure_directory(directory)
                    created_dirs.append(directory)
                    logging.info(f"Successfully created secure directory: {directory}")
                except Exception as e:
                    logging.error(f"Failed to create directory {directory}: {e}")
                    if directory == self.data_dir:
                        raise RuntimeError(f"Cannot create main data directory: {e}")
            
            # Verify all directories were created securely
            self._verify_directory_security(created_dirs)
            
            # Set up additional security measures
            self._setup_directory_protections(created_dirs)
            
            logging.info("All secure directories created and verified successfully")
            
        except Exception as e:
            # Clean up any partially created directories on failure
            self._cleanup_partial_setup(created_dirs)
            logging.critical(f"Failed to setup secure directories: {e}")
            raise RuntimeError(f"Secure directory setup failed: {e}")

    def _create_secure_directory(self, directory_path: str) -> None:
        """ Create a single directory with maximum security settings """
        try:
            # Check if directory already exists
            if os.path.exists(directory_path):
                # Verify existing directory security
                if not self._is_directory_secure(directory_path):
                    raise RuntimeError(f"Existing directory {directory_path} has insecure permissions")
                logging.info(f"Using existing secure directory: {directory_path}")
                return
            
            # Create directory with secure permissions
            os.makedirs(directory_path, mode=0o700, exist_ok=False)
            
            # Verify the directory was actually created
            if not os.path.exists(directory_path):
                raise RuntimeError(f"Directory creation failed: {directory_path}")
                
            # Set secure permissions, ensures security
            if os.name != 'nt':  # Windows has different permission model
                os.chmod(directory_path, 0o700)
                
            # Verify permissions were set correctly
            if not self._is_directory_secure(directory_path):
                raise RuntimeError(f"Failed to set secure permissions for: {directory_path}")
                
            logging.debug(f"Created secure directory: {directory_path}")
            
        except FileExistsError:
            # Directory was created by another process, verify it's secure
            if not self._is_directory_secure(directory_path):
                raise RuntimeError(f"Directory created by another process has insecure permissions: {directory_path}")
        except Exception as e:
            logging.error(f"Failed to create secure directory {directory_path}: {e}")
            raise

    def _is_directory_secure(self, directory_path: str) -> bool:
        """ Verify directory has secure permissions with macOS-specific checks"""
        try:
            if not os.path.exists(directory_path):
                return False
                
            system = platform.system()
            
            if system == "Darwin":  # macOS
                import stat
                try:
                    dir_stat = os.stat(directory_path)
                    permissions = stat.S_IMODE(dir_stat.st_mode)
                    
                    # On macOS, verify the directory is owned by current user
                    if dir_stat.st_uid != os.getuid():
                        logging.warning(f"Directory {directory_path} not owned by current user (UID: {dir_stat.st_uid}, current: {os.getuid()})")
                        return False
                    
                    # Check for secure permissions
                    # Owner must have read/write/execute (0o700)
                    owner_perms = permissions & 0o700
                    if owner_perms != 0o700:
                        logging.warning(f"Directory {directory_path} owner lacks full permissions: {oct(permissions)}")
                        return False
                    
                    # Check if accessible by group or others
                    if permissions & 0o077:  # World-readable/executable
                        logging.warning(f"Directory {directory_path} has world-accessible permissions: {oct(permissions)}")
                        return False
                        
                    # For macOS, we're stricter about group permissions
                    if permissions & 0o070:  # Group permissions
                        # Allow group permissions only if it's exactly 0o750 and we're in a shared scenario
                        if permissions != 0o750:
                            logging.warning(f"Directory {directory_path} has insecure group permissions: {oct(permissions)}")
                            return False
                    
                    return True
                    
                except Exception as e:
                    logging.error(f"Error checking macOS directory permissions for {directory_path}: {e}")
                    # Fall back to write test
                    return self._test_directory_access(directory_path)
                    
            elif os.name == 'nt':  # Windows
                # Keep your existing Windows logic
                try:
                    # Try to create a test file to verify we have write access
                    test_file = os.path.join(directory_path, f".security_test_{secrets.token_hex(8)}.tmp")
                    with open(test_file, 'w') as f:
                        f.write("security_test")
                    os.remove(test_file)
                    return True
                except (PermissionError, OSError):
                    return False
                except Exception:
                    # For other errors, assume it's usable
                    return True
            else:  # Other Unix-like systems (Linux, BSD, etc.)
                import stat
                try:
                    dir_stat = os.stat(directory_path)
                    permissions = stat.S_IMODE(dir_stat.st_mode)
                    
                    # Check if directory is accessible only by owner (0o700)
                    secure_permissions = 0o700
                    if permissions == secure_permissions:
                        return True
                    else:
                        # For existing directories, allow if owner has read/write/execute even if group/others have some permissions
                        owner_perms = (permissions & 0o700)
                        if owner_perms == 0o700:  # Owner has full control
                            logging.warning(f"Directory {directory_path} has non-strict permissions but owner has full control: {oct(permissions)}")
                            return True
                        else:
                            return False
                except Exception:
                    # If we can't check permissions, assume it's usable
                    return True
                    
        except Exception as e:
            logging.error(f"Error checking directory security for {directory_path}: {e}")
            # If can't determine security return False
            return False

    def _test_directory_access(self, directory_path: str) -> bool:
        """ Test if can read/write to a directory as a fallback check """
        try:
            test_file = os.path.join(directory_path, f".access_test_{secrets.token_hex(8)}.tmp")
            # Test write
            with open(test_file, 'w') as f:
                f.write("test")
            # Test read
            with open(test_file, 'r') as f:
                content = f.read()
            # Test delete
            os.remove(test_file)
            return content == "test"
        except Exception:
            return False

    def _verify_directory_security(self, directories: List[str]) -> None:
        """Verify all directories meet security requirements """
        insecure_dirs = []
        
        for directory in directories:
            if not self._is_directory_secure(directory):
                insecure_dirs.append(directory)
        
        if insecure_dirs:
            insecure_list = "\n".join(insecure_dirs)
            raise RuntimeError(f"The following directories have insecure permissions:\n{insecure_list}")

    def _setup_directory_protections(self, directories: List[str]) -> None:
        """ Set up additional security protections for directories """
        try:
            for directory in directories:
                # Create .htaccess equivalent protection
                self._create_directory_protection_file(directory)
                
                # Set directory attributes if supported
                if os.name != 'nt':
                    try:
                        # Make directory immutable if possible (requires root)
                        pass
                    except Exception:
                        pass 
                        
        except Exception as e:
            logging.warning(f"Could not setup additional directory protections: {e}")


    def _create_directory_protection_file(self, directory: str) -> None:
        """ Create a protection file to indicate directory contains sensitive data """
        try:
            protection_file = os.path.join(directory, "SECURE_DATA_WARNING.txt")
            warning_content = """SECURITY WARNING

    This directory contains encrypted password data for Secure Password Manager.

    DO NOT:
    - Modify files in this directory manually
    - Change directory permissions
    - Move or copy these files to insecure locations
    - Share these files with others

    These files are encrypted but should still be treated as sensitive data.
    """
            with open(protection_file, 'w', encoding='utf-8') as f:
                f.write(warning_content)
                
            # Set secure permissions on the protection file too
            if os.name != 'nt':
                os.chmod(protection_file, 0o600)
                
        except Exception as e:
            logging.warning(f"Could not create protection file in {directory}: {e}")

    def _cleanup_partial_setup(self, created_directories: List[str]) -> None:
        """ Clean up partially created directories on setup failure """
        if not created_directories:
            return
            
        logging.warning("Cleaning up partially created directories due to setup failure")
        
        for directory in reversed(created_directories):  # Clean up in reverse order
            try:
                if os.path.exists(directory):
                    # Only remove if directory is empty (safety check)
                    if not os.listdir(directory):
                        os.rmdir(directory)
                        logging.info(f"Cleaned up directory: {directory}")
                    else:
                        logging.warning(f"Directory {directory} not empty, skipping cleanup")
            except Exception as e:
                logging.error(f"Failed to cleanup directory {directory}: {e}")

    def get_secure_fallback_directory(self) -> str:
        """ Get a secure fallback directory for emergency use only """
        # Use user-specific temp directory rather than system temp
        import tempfile
        user_temp = tempfile.gettempdir()
        uid = str(os.getuid()) if hasattr(os, "getuid") else os.getenv("USERNAME", "user")
        fallback_dir = os.path.join(user_temp, f"spm_secure_fallback_{uid}")
        
        try:
            os.makedirs(fallback_dir, mode=0o700, exist_ok=True)
            
            # Add extra protection - create a marker file
            marker_file = os.path.join(fallback_dir, "FALLBACK_EMERGENCY_ONLY.txt")
            with open(marker_file, 'w') as f:
                f.write("EMERGENCY FALLBACK - MOVE DATA TO SECURE LOCATION ASAP")
                
            logging.critical(f"Using secure fallback directory: {fallback_dir}")
            return fallback_dir
            
        except Exception as e:
            logging.critical(f"CRITICAL: Cannot create secure fallback directory: {e}")
            # Final fallback - current directory with warning
            current_dir_fallback = os.path.join(os.getcwd(), "spm_emergency_data")
            os.makedirs(current_dir_fallback, mode=0o700, exist_ok=True)
            logging.critical(f"USING CURRENT DIRECTORY FALLBACK: {current_dir_fallback}")
            return current_dir_fallback

    def get_user_database_path(self, username: str) -> str:
        """ Get secure database path for user with sanitized username            
        Security Features:
            -Username sanitization to prevent path traversal attacks
            -Fallback to safe default if username is invalid
            -Consistent naming convention """
        # Sanitize username to prevent path traversal attacks
        safe_username = "".join(c for c in username if c.isalnum() or c in ('-', '_')).rstrip()
        if not safe_username:
            safe_username = "default_user"  # Fallback for invalid usernames
            logging.warning(f"Username sanitized to fallback: {safe_username}")

        return os.path.join(self.data_dir, f"user_{safe_username}.db")  # ✅
    
    def _secure_chmod_file(self, file_path: str) -> None:
        """ Restrict a sensitive file to owner-read/write only (0600) """
        if os.name == 'nt':
            return
        try:
            os.chmod(file_path, 0o600)
        except OSError as e:
            logging.warning(f"Could not set secure permissions on {file_path}: {e}")

    def load_profiles(self) -> Dict[str, Any]:
        """ Load user profiles with proper error handling """
        try:
            if os.path.exists(self.profiles_file):
                with open(self.profiles_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            else:
                logging.info("Profiles file not found, returning empty profiles")
        except (IOError, json.JSONDecodeError) as e:
            logging.error(f"Error loading profiles: {e}")
        return {}
        
    def save_profiles(self, profiles: Dict[str, Any]) -> bool:
        """ Save user profiles with proper error handling """
        try:
            with open(self.profiles_file, 'w', encoding='utf-8') as f:
                json.dump(profiles, f, indent=2)
            self._secure_chmod_file(self.profiles_file)
            logging.info("Profiles saved successfully")
            return True
        except IOError as e:
            logging.error(f"Failed to save profiles: {e}")
            return False
            
    def load_salts(self) -> Dict[str, str]:
        """ Load salts from file with proper error handling """
        try:
            if os.path.exists(self.salt_file):
                with open(self.salt_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            else:
                logging.info("Salts file not found, returning empty salts")
        except (IOError, json.JSONDecodeError) as e:
            logging.error(f"Error loading salts: {e}")
        return {}
        
    def save_salts(self, salts: Dict[str, str]) -> bool:
        """ Save salts to file with proper error handling """
        try:
            with open(self.salt_file, 'w', encoding='utf-8') as f:
                json.dump(salts, f, indent=2)
            self._secure_chmod_file(self.salt_file)
            logging.info("Salts saved successfully")
            return True
        except IOError as e:
            logging.error(f"Failed to save salts: {e}")
            return False
            
    # Persisted brute-force / lockout tracking
    def load_login_attempts(self) -> Dict[str, Dict[str, Any]]:
        """ Load persisted login-attempt / lockout state """
        try:
            if os.path.exists(self.login_attempts_file):
                with open(self.login_attempts_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except (IOError, json.JSONDecodeError) as e:
            logging.error(f"Error loading login attempts: {e}")
        return {}

    def save_login_attempts(self, attempts: Dict[str, Dict[str, Any]]) -> bool:
        """Persist login-attempt / lockout state."""
        try:
            with open(self.login_attempts_file, 'w', encoding='utf-8') as f:
                json.dump(attempts, f, indent=2)
            self._secure_chmod_file(self.login_attempts_file)
            return True
        except IOError as e:
            logging.error(f"Failed to save login attempts: {e}")
            return False

    # Persisted TOTP replay-protection state
    def load_totp_state(self) -> Dict[str, int]:
        """ Load the last-accepted TOTP time-step per username """
        try:
            if os.path.exists(self.totp_state_file):
                with open(self.totp_state_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except (IOError, json.JSONDecodeError) as e:
            logging.error(f"Error loading TOTP state: {e}")
        return {}

    def save_totp_state(self, state: Dict[str, int]) -> bool:
        """ Persist the last-accepted TOTP time-step per username """
        try:
            with open(self.totp_state_file, 'w', encoding='utf-8') as f:
                json.dump(state, f, indent=2)
            self._secure_chmod_file(self.totp_state_file)
            return True
        except IOError as e:
            logging.error(f"Failed to save TOTP state: {e}")
            return False

    def get_user_salt(self, username: str) -> bytes:
        """ Get or create salt for a user """
        salts = self.load_salts()
        if username in salts:
            try:
                return base64.b64decode(salts[username])
            except Exception as e:
                logging.error(f"Error decoding salt for {username}: {e}")
                # Generate new salt if decoding fails
                new_salt = self.security_manager.generate_salt()
                salts[username] = base64.b64encode(new_salt).decode()
                self.save_salts(salts)
                return new_salt
        else:
            # Generate new salt for new user
            new_salt = self.security_manager.generate_salt()
            salts[username] = base64.b64encode(new_salt).decode()
            self.save_salts(salts)
            return new_salt

    def _get_integrity_key(self) -> Optional[bytes]:
        try:
            main_key = self.security_manager.encryption_key
        except RuntimeError:
            return None
        return hashlib.sha256(main_key + b"|pm2-integrity-hmac-v1").digest()

    def calculate_checksum(self, data: Any) -> str:
        """ Calculate an integrity value for a blob of (already-encrypted) data """
        if isinstance(data, str):
            data = data.encode('utf-8')

        integrity_key = self._get_integrity_key()
        if integrity_key is not None:
            return hmac.new(integrity_key, data, hashlib.sha256).hexdigest()

        logging.debug("No session key available — using unauthenticated checksum fallback")
        return hashlib.sha256(data).hexdigest()

    def load_checksums(self) -> Dict[str, str]:
        """ Load database checksums for integrity verification """
        try:
            if os.path.exists(self.checksum_file):
                with open(self.checksum_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except (IOError, json.JSONDecodeError) as e:
            logging.error(f"Error loading checksums: {e}")
        return {}
        
    def save_checksums(self, checksums: Dict[str, str]) -> bool:
        """ Save database checksums  """
        try:
            with open(self.checksum_file, 'w', encoding='utf-8') as f:
                json.dump(checksums, f, indent=2)
            self._secure_chmod_file(self.checksum_file)
            return True
        except IOError as e:
            logging.error(f"Failed to save checksums: {e}")
            return False
            
    def verify_database_integrity(self, file_path: str) -> Tuple[bool, str]:
        """ Verify database integrity using checksum and file permissions            
        Security Features:
            -File existence checking
            -Checksum verification
            -File permission checking (Unix systems)
            -Comprehensive error handling """
        try:
            if not os.path.exists(file_path):
                return False, "Database file not found"
                
            # Check file permissions on Unix-like systems
            if os.name != 'nt':
                stat_info = os.stat(file_path)
                if stat_info.st_mode & 0o077:  # Check if accessible by group/others
                    return False, "Insecure file permissions detected"
                
            checksums = self.load_checksums()
            current_checksum = checksums.get(file_path)
            
            if not current_checksum:
                return True, "No previous checksum found"
                
            with open(file_path, 'rb') as f:
                file_data = f.read()
                
            calculated_checksum = self.calculate_checksum(file_data)
            
            if current_checksum == calculated_checksum:
                return True, "Integrity verified"
            else:
                return False, "Database integrity check failed - file may be corrupted"
                
        except Exception as e:
            return False, f"Integrity check error: {str(e)}"
            
    def update_database_checksum(self, file_path: str) -> bool:
        """ Update checksum for database file """
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
                
            checksums = self.load_checksums()
            checksums[file_path] = self.calculate_checksum(file_data)
            return self.save_checksums(checksums)
        except Exception as e:
            logging.error(f"Failed to update checksum: {e}")
            return False

    def load_data(self, file_path: Optional[str] = None) -> List[Dict[str, str]]:
        """ Load data from encrypted database file with integrity check """
        if file_path is None:
            logging.error("No file path provided for load_data")
            return []

        try:
            if not os.path.exists(file_path):
                logging.info(f"Database file not found: {file_path}")
                return []

            # Check file permissions on Unix-like systems without rereading the database.
            if os.name != 'nt':
                stat_info = os.stat(file_path)
                if stat_info.st_mode & 0o077:
                    logging.warning(f"Database integrity warning for {file_path}: insecure file permissions detected")

            with open(file_path, 'r', encoding='utf-8') as f:
                encrypted_data = f.read()

            if not encrypted_data:
                logging.info(f"Empty database file: {file_path}")
                return []

            # Verify checksum against the encrypted payload already in memory.
            checksums = self.load_checksums()
            current_checksum = checksums.get(file_path)
            if current_checksum:
                calculated_checksum = self.calculate_checksum(encrypted_data.encode('utf-8'))
                if current_checksum != calculated_checksum:
                    logging.warning(
                        f"Database integrity warning for {file_path}: checksum mismatch; file may be corrupted"
                    )
            else:
                logging.info(f"No previous checksum found for {file_path}")

            decrypted_data = self.security_manager.decrypt_data(encrypted_data)
            if decrypted_data:
                try:
                    data = json.loads(decrypted_data)
                    if not isinstance(data, list):
                        logging.error(f"Invalid database format: expected list, got {type(data)}")
                        return []
                    return data
                except json.JSONDecodeError as e:
                    logging.error(f"Database JSON corruption in {file_path}: {e}")
                    return []

            logging.error(f"Failed to decrypt data from {file_path}")
            return []
        except Exception as e:
            logging.error(f"Load error for {file_path}: {e}")
            return []

    def save_data(self, data: List[Dict[str, str]], file_path: Optional[str] = None) -> bool:
        """ Save data to encrypted database file and update checksum """
        if file_path is None:
            logging.error("No file path provided for save_data")
            return False
            
        try:
            # Ensure the directory exists
            directory = os.path.dirname(file_path)
            if directory:  # Only create directories if path contains them
                os.makedirs(directory, exist_ok=True)
            
            # Compact JSON keeps the encrypted database smaller to reduce read/decrypt/parse time on the next startup
            json_data = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
            encrypted_data = self.security_manager.encrypt_data(json_data)

            # Atomic write
            tmp_path = file_path + ".tmp"
            with open(tmp_path, 'w', encoding='utf-8') as f:
                f.write(encrypted_data)
                f.flush()
                os.fsync(f.fileno())  # Flush OS write buffer to disk
            self._secure_chmod_file(tmp_path) # Lock down before the rename is visible
            os.replace(tmp_path, file_path) # Atomic on POSIX; best-effort on Windows
            self._secure_chmod_file(file_path) # Belt-and-suspenders after rename
            
            # Update checksum after successful save
            self.update_database_checksum(file_path)
            logging.info(f"Data saved successfully to {file_path}")
            return True
        except Exception as e:
            logging.error(f"Save data error for path '{file_path}': {e}")
            return False

    def ensure_database_exists(self, file_path: str) -> bool:
        """ Ensure database file exists, create empty one if it doesn't """
        if not os.path.exists(file_path):
            logging.info(f"Creating new database file: {file_path}")
            return self.save_data([], file_path)
        return True