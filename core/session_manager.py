"""Session management: auto-lock, activity tracking, login-attempt throttling."""
import logging
import time
import tkinter as tk
from typing import Callable, Dict, Optional

from config.constants import ACCOUNT_LOCKOUT_TIME, LOCK_TIMEOUT, MAX_LOGIN_ATTEMPTS


class SessionManager:
    """ Manages user session lifecycle for the password manager.
    -Auto-lock after a configurable period of inactivity
    -Track and throttle failed login attempts (account lockout)
    -Provide activity-timer reset hooks for tkinter event bindings """

    def __init__(
        self,
        root: tk.Tk,
        audit_logger,
        on_lock: Optional[Callable[[], None]] = None,
    ) -> None:
        self.root          = root
        self.audit_logger  = audit_logger
        self.on_lock       = on_lock

        # Session state — updated by the UI after login/logout
        self.current_user: Optional[str] = None
        self.is_locked: bool             = False

        # Brute-force tracking
        self.login_attempts: Dict[str, int]   = {}
        self.lockout_time:   Dict[str, float] = {}

        # Inactivity tracking
        self.last_activity: float = time.time()

    # Session state updates
    def on_login(self, username: str) -> None:
        """Call this after a successful login to activate inactivity tracking."""
        self.current_user  = username
        self.is_locked     = False
        self.last_activity = time.time()
        logging.info(f"Session started for '{username}'")

    def on_logout(self) -> None:
        """Call this on explicit logout to clear session state."""
        logging.info(f"Session ended for '{self.current_user}'")
        self.current_user = None
        self.is_locked    = False

    # Auto-lock
    def setup_auto_lock(self) -> None:
        self.root.bind('<KeyPress>',    self._reset_activity_timer)
        self.root.bind('<ButtonPress>', self._reset_activity_timer)
        self.root.bind('<Motion>',      self._reset_activity_timer)
        self._check_auto_lock()

    def lock_application(self) -> None:
        """ Lock the application immediately """
        if self.is_locked:
            return 

        self.is_locked = True
        logging.info(f"Application locked for user '{self.current_user}'")

        if self.current_user and self.audit_logger:
            try:
                self.audit_logger.log_security_event(
                    self.current_user, "APP_LOCKED", "Application locked due to inactivity"
                )
            except Exception as e:
                logging.error(f"Audit log error on lock: {e}")

        if callable(self.on_lock):
            try:
                self.on_lock()
            except Exception as e:
                logging.error(f"on_lock callback error: {e}")

    def unlock_application(self) -> None:
        """ Unlock after the user re-authenticates on the lock screen """
        self.is_locked     = False
        self.last_activity = time.time()
        logging.info(f"Application unlocked for user '{self.current_user}'")

    def _reset_activity_timer(self, event: Optional[tk.Event] = None) -> None:
        """ Reset the inactivity timer on any user interaction """
        if not self.is_locked and self.current_user:
            self.last_activity = time.time()

    def _check_auto_lock(self) -> None:
        """ Called every second via root.after(). Locks the app when the inactivity threshold is exceeded """
        if (
            not self.is_locked
            and self.current_user
            and time.time() - self.last_activity > LOCK_TIMEOUT
        ):
            logging.info("Auto-lock triggered due to inactivity")
            self.lock_application()

        # Reschedule regardless of lock state to detect unlock→re-idle
        self.root.after(1000, self._check_auto_lock)

    # Login-attempt throttling
    def is_account_locked(self, username: str) -> bool:
        if username in self.lockout_time:
            if time.time() < self.lockout_time[username]:
                return True
            # Lockout expired — reset
            del self.lockout_time[username]
            self.login_attempts[username] = 0
            logging.info(f"Lockout expired for '{username}', attempts reset")
        return False

    def get_remaining_lockout_seconds(self, username: str) -> int:
        """ Return seconds remaining in the lockout period, or 0 if not locked """
        if username in self.lockout_time:
            return max(0, int(self.lockout_time[username] - time.time()))
        return 0

    def record_failed_login(self, username: str) -> dict:
        """ Record a failed login attempt and apply a lockout if the threshold is reached"""
        self.login_attempts[username] = self.login_attempts.get(username, 0) + 1
        attempts = self.login_attempts[username]

        if attempts >= MAX_LOGIN_ATTEMPTS:
            self.lockout_time[username] = time.time() + ACCOUNT_LOCKOUT_TIME
            logging.warning(f"Account '{username}' locked after {attempts} failed attempts")

            if self.audit_logger:
                try:
                    self.audit_logger.log_login(
                        username, False, "Account locked — too many failed attempts"
                    )
                except Exception as e:
                    logging.error(f"Audit log error: {e}")

            return {
                "locked":    True,
                "attempts":  attempts,
                "remaining": int(ACCOUNT_LOCKOUT_TIME),
            }

        logging.info(f"Failed login attempt {attempts}/{MAX_LOGIN_ATTEMPTS} for '{username}'")
        return {
            "locked":    False,
            "attempts":  attempts,
            "remaining": 0,
        }

    def record_successful_login(self, username: str) -> None:
        """ Clear failed-attempt counters after a successful login """
        self.login_attempts.pop(username, None)
        self.lockout_time.pop(username, None)
        logging.info(f"Successful login for '{username}' — attempt counter cleared")

    def get_login_attempts(self, username: str) -> int:
        """ Return the current failed-attempt count for a username """
        return self.login_attempts.get(username, 0)