"""Handles security audit logging"""
import logging
import os
from typing import Optional

from config.constants import LOGS_DIR

class AuditLogger:
    """ Handles security audit logging for compliance and monitoring.    
    -Log security events and user actions
    -Maintain audit trail for compliance
    -Secure log file management
    -Event categorization and tracking    
    Logged Events:
    -Login attempts (success/failure)
    -Password access and modifications
    -Database operations
    -Security configuration changes
    -User management actions """
    
    def __init__(self):
        """ Initialize AuditLogger with secure log directory """
        self.logs_dir = LOGS_DIR
        os.makedirs(self.logs_dir, exist_ok=True)
        self.audit_log_file = os.path.join(self.logs_dir, "audit.log")
        self.setup_audit_logging()
        
    def setup_audit_logging(self) -> None:
        """ Setup audit logging configuration with file handler and formatter """
        try:
            audit_handler = logging.FileHandler(self.audit_log_file, encoding='utf-8')
            audit_handler.setFormatter(logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s'
            ))
            
            self.audit_logger = logging.getLogger('audit')
            self.audit_logger.setLevel(logging.INFO)
            self.audit_logger.addHandler(audit_handler)
            self.audit_logger.propagate = False  # Prevent propagation to root logger
            logging.info("Audit logging configured successfully")
        except Exception as e:
            logging.error(f"Failed to setup audit logging: {e}")
        
    def log_event(self, event_type: str, username: str, details: str, success: bool = True) -> None:
        """ Log an audit event with standardized format """
        status = "SUCCESS" if success else "FAILED"
        message = f"{event_type} - User: {username} - {details} - {status}"
        self.audit_logger.info(message)
        
    def log_login(self, username: str, success: bool = True, details: str = "") -> None:
        """ Log login attempt with success/failure status """
        self.log_event("LOGIN", username, details, success)
        
    def log_password_access(self, username: str, website: str, action: str) -> None:
        """ Log password access event (view, copy, edit, delete, add)"""
        details = f"Website: {website} - Action: {action}"
        self.log_event("PASSWORD_ACCESS", username, details)
        
    def log_database_operation(self, username: str, operation: str, 
                             database_path: str, success: bool = True) -> None:
        """ Log database operation (save, load, backup, export, import) """
        details = f"Operation: {operation} - Database: {database_path}"
        self.log_event("DATABASE_OPERATION", username, details, success)
        
    def log_security_event(self, username: str, event: str, details: str) -> None:
        """ Log security-related event (password change, 2FA change, etc.) """
        self.log_event("SECURITY_EVENT", username, f"{event} - {details}")
