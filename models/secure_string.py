"""Secure string handling with memory protection"""
import logging
from typing import Optional

class SecureString:
    """Simplified secure string storage"""
    
    def __init__(self):
        self._data = bytearray()
        
    def set(self, value: str) -> None:
        """Set the secure string value"""
        self.clear()  # Clear any existing value
        self._data.extend(value.encode('utf-8'))
        
    def get(self) -> str:
        """Get the secure string value"""
        return self._data.decode('utf-8')
        
    def clear(self) -> None:
        """Overwrite every byte with zero"""
        for i in range(len(self._data)):
            self._data[i] = 0
        self._data.clear()
        
    def get_secure_context(self):
        """Context manager for secure access"""
        class SecureContext:
            def __init__(self, secure_str):
                self.secure_str = secure_str
                
            def __enter__(self):
                return self.secure_str.get()
                
            def __exit__(self, exc_type, exc_val, exc_tb):
                pass
                
        return SecureContext(self)
        
    def __len__(self) -> int:
        return len(self._data)
        
    def __bool__(self) -> bool:
        return bool(self._data)