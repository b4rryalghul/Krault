"""Main application entry point"""
import sys
import os

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ui.screens import PasswordManager
from core.database_manager import DatabaseManager
from core.security_service import SecurityService
from core.session_manager import SessionManager
from ui.theme_manager import ThemeManager
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

def main():
    root = tk.Tk()
    app = PasswordManager(root)
    root.mainloop()

if __name__ == "__main__":
    main()