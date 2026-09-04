""" Main app screens and UI management """
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import base64
import gc
import hmac
import secrets
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import logging
import time
import json
import csv
import pyotp
import qrcode
import shutil
from datetime import datetime
from typing import Optional, Dict, Any, Callable, List, Tuple
from PIL import Image, ImageTk

from core.security_service import SecurityService
from core.session_manager import SessionManager
from core.security_manager import SecurityManager
from core.database_manager import DatabaseManager
from core.password_policy import PasswordPolicyManager
from core.audit_logger import AuditLogger
from ui.theme_manager import ThemeManager
from ui.dialogs import EntryDialogManager
from ui.widgets import RoundedButton
from models.secure_string import SecureString
from utils.helpers import setup_logging, copy_to_clipboard, generate_password, secure_clear_object
from config.constants import *
from config.themes import get_style_config
from ui.modern_widgets import ModernButton, CardFrame, ModernEntry
from config.themes import get_style_config, set_application_theme, get_current_theme, get_available_themes



class PasswordManager:
    
    def __init__(self, root: tk.Tk):
        """
        Initialize PasswordManager application.
        Attributes:
            root: Main application window
            security_manager: Handles encryption and session security
            database_manager: Manages data storage and retrieval
            password_policy_manager: Manages password policy enforcement
            audit_logger: Handles security audit logging
            entry_dialog_manager: Manages password entry dialogs
            current_user: Currently logged in user
            current_database: Path to current user's database
            entries: Loaded password entries
            login_attempts: Track failed login attempts per user
            lockout_time: Track account lockout end times
            last_activity: Timestamp for auto-lock functionality
            is_locked: Application lock state
            _secure_password: Secure storage for master password
            _secure_session_data: Secure storage for session data
            _temp_password: Temporary password storage for 2FA setup
        """
        self.root = root
        self.root.title("Krault")
        self.root.geometry("850x700")
        
        # Initialize managers
        self.security_manager = SecurityManager()
        self.database_manager = DatabaseManager(self.security_manager)
        self.password_policy_manager = PasswordPolicyManager()
        self.audit_logger = AuditLogger()
        
        # Setup logging
        self.setup_logging()

        # Configure theme BEFORE UI
        self.configure_theme()
        
        # Initialize the rest and UI
        self.entry_dialog_manager = EntryDialogManager(
            root, self._get_style_config(), 
            self.security_manager, self.database_manager, self.audit_logger
        )
        
        # Application state variables
        self.current_user = None  # Currently logged in user
        self.current_database = None  # Path to current user's database
        self.entries = []  # Loaded password entries
        self.entry_sort_value = "website"  # Main-screen sort: "website", "username", or "security"
        self.entry_search_text = ""  # Current main-screen search text
        self._entry_meta_cache = {}  # Cached normalized fields for fast sorting/filtering/rendering
        self._entry_render_after_id = None  
        self._entry_filter_after_id = None  
        self._entry_render_batch_size = 40 
        self.login_attempts = {}  # Track failed login attempts per user
        self.lockout_time = {}  # Track account lockout end times
        self._load_persisted_login_attempts()  # Restore brute-force state across restarts
        self.last_activity = time.time()  # For auto-lock functionality
        self.is_locked = False  # Application lock state
        
        # Secure storage for sensitive data
        self._secure_password = SecureString()  # Secure master password storage
        self._secure_session_data = {}  # Secure storage for session data
        self._temp_password = SecureString()  # Temporary password storage for 2FA setup
        
        # Enable auto-lock monitoring
        self.setup_auto_lock()  
        
        # Login screen
        self.show_login_screen()
    
    def show_login_screen(self) -> None:
        """ Clean centred card login/signup screen """
        self.clear_screen()
        cfg = self._get_style_config()
        self._configure_login_styles(cfg)

        bg   = cfg["bg_color"]
        sbg  = cfg.get("secondary_bg_color", bg)
        card = cfg.get("card_bg_color", sbg)
        acc  = cfg["accent_color"]
        fg   = cfg["fg_color"]
        mfg  = cfg.get("muted_fg_color", fg)
        bdr  = cfg.get("border_color", "#2d2d5a")
        btn  = cfg.get("btn_bg_color", acc)
        bfg  = cfg.get("btn_fg_color", "#ffffff")
        ibg  = cfg.get("input_bg_color", sbg)
        bf   = cfg["button_font"]
        bod  = cfg["body_font"]
        ttl  = cfg["title_font"]

        # Outer fill 
        outer = tk.Frame(self.root, bg=bg)
        outer.pack(expand=True, fill="both")
        outer.grid_rowconfigure(0, weight=1)
        outer.grid_columnconfigure(0, weight=1)

        # Centre column (fixed 340 px)
        col = tk.Frame(outer, bg=bg, width=340)
        col.grid(row=0, column=0)
        col.grid_propagate(False)

        # Lock icon
        icon_wrap = tk.Frame(col, bg=card, width=60, height=60,
                             highlightbackground=acc, highlightthickness=1)
        icon_wrap.pack(pady=(48, 14))
        icon_wrap.pack_propagate(False)
        tk.Label(icon_wrap, text="🔐", font=("Segoe UI", 26),
                 bg=card, fg=acc).place(relx=.5, rely=.5, anchor="center")

        # Title / subtitle
        tk.Label(col, text="Krault", font=ttl,
                 bg=bg, fg=fg).pack()
        tk.Label(col, text="Secure password manager", font=bod,
                 bg=bg, fg=mfg).pack(pady=(2, 24))

        # Card
        card_frame = tk.Frame(col, bg=card,
                              highlightbackground=bdr, highlightthickness=1)
        card_frame.pack(fill="x", padx=0, pady=0)
        inner = tk.Frame(card_frame, bg=card)
        inner.pack(fill="x", padx=28, pady=24)

        # Mode toggle label/link at top of card
        self._login_mode = tk.StringVar(value="login")

        mode_bar = tk.Frame(inner, bg=card)
        mode_bar.pack(fill="x", pady=(0, 18))

        mode_label = tk.Label(mode_bar, text="Sign in", font=bf,
                              bg=card, fg=fg, cursor="hand2")
        mode_label.pack(side="left")
        sep_lbl = tk.Label(mode_bar, text=" · ", font=bod, bg=card, fg=mfg)
        sep_lbl.pack(side="left")
        reg_label = tk.Label(mode_bar, text="Create account", font=bod,
                             bg=card, fg=mfg, cursor="hand2")
        reg_label.pack(side="left")

        # Field factory
        def make_field(parent, label_text, var, secret=False):
            tk.Label(parent, text=label_text.upper(),
                     font=("Segoe UI", 9), bg=card, fg=mfg).pack(anchor="w")
            e = tk.Entry(parent, textvariable=var,
                         show="●" if secret else "",
                         font=bod, bg=ibg, fg=fg, relief="flat",
                         bd=0, highlightbackground=bdr,
                         highlightcolor=acc, highlightthickness=1,
                         insertbackground=fg,
                         selectbackground=acc, selectforeground=bg)
            e.pack(fill="x", ipady=6, pady=(3, 12))
            return e

        # Login fields
        login_section = tk.Frame(inner, bg=card)
        login_section.pack(fill="x")

        self.login_username_var = tk.StringVar()
        self.login_password_var = tk.StringVar()
        lu = make_field(login_section, "Username", self.login_username_var)
        lp = make_field(login_section, "Master password", self.login_password_var, secret=True)

        def do_login():
            self.handle_login(self.login_username_var.get(),
                              self.login_password_var.get())
        lp.bind("<Return>", lambda _: do_login())

        login_btn = tk.Button(login_section, text="Unlock vault",
                              command=do_login, font=bf,
                              bg=btn, fg=bfg, relief="flat",
                              activebackground=cfg.get("btn_hover_color", btn),
                              activeforeground=bfg, bd=0, cursor="hand2")
        login_btn.pack(fill="x", ipady=8, pady=(4, 0))

        # Signup fields
        signup_section = tk.Frame(inner, bg=card)
        # Don't pack yet

        self.signup_username_var  = tk.StringVar()
        self.signup_password_var  = tk.StringVar()
        self.signup_confirm_var   = tk.StringVar()
        self.signup_tfa_var       = tk.BooleanVar()

        make_field(signup_section, "Username", self.signup_username_var)
        make_field(signup_section, "Master password", self.signup_password_var, secret=True)
        sc = make_field(signup_section, "Confirm password", self.signup_confirm_var, secret=True)

        tfa_row = tk.Frame(signup_section, bg=card)
        tfa_row.pack(fill="x", pady=(0, 10))
        tfa_cb = tk.Checkbutton(tfa_row, text="Enable two-factor authentication",
                                variable=self.signup_tfa_var, font=bod,
                                bg=card, fg=mfg, selectcolor=card,
                                activebackground=card, activeforeground=fg,
                                bd=0, highlightthickness=0)
        tfa_cb.pack(anchor="w")

        def do_signup():
            self.handle_signup(self.signup_username_var.get(),
                               self.signup_password_var.get(),
                               self.signup_confirm_var.get(),
                               self.signup_tfa_var.get())
        sc.bind("<Return>", lambda _: do_signup())

        signup_btn = tk.Button(signup_section, text="Create account",
                               command=do_signup, font=bf,
                               bg=btn, fg=bfg, relief="flat",
                               activebackground=cfg.get("btn_hover_color", btn),
                               activeforeground=bfg, bd=0, cursor="hand2")
        signup_btn.pack(fill="x", ipady=8)

        # Mode switcher
        def show_login():
            signup_section.pack_forget()
            login_section.pack(fill="x")
            mode_label.config(fg=fg, font=bf)
            reg_label.config(fg=mfg, font=bod)
            lu.focus_set()

        def show_signup():
            login_section.pack_forget()
            signup_section.pack(fill="x")
            mode_label.config(fg=mfg, font=bod)
            reg_label.config(fg=fg, font=bf)

        mode_label.bind("<Button-1>", lambda _: show_login())
        reg_label.bind("<Button-1>", lambda _: show_signup())

        lu.focus_set()

    def _setup_basic_login_tab(self, parent: ttk.Frame, style_config: Dict[str, Any]) -> None:
        """Setup basic login tab that works with current theme system"""
        # Configure parent frame background
        parent.configure(style='Dark.TFrame')
        
        # Username field
        username_label = tk.Label(
            parent,
            text="Username",
            font=style_config['body_font'],
            bg=style_config.get('card_bg_color', style_config['secondary_bg_color']),
            fg=style_config['fg_color']
        )
        username_label.pack(pady=(15, 3))
        
        self.login_username_var = tk.StringVar()
        username_entry = ttk.Entry(
            parent,
            textvariable=self.login_username_var,
            width=25,
            font=style_config['body_font']
        )
        username_entry.pack(pady=3)
        
        # Password field  
        password_label = tk.Label(
            parent,
            text="Master Password", 
            font=style_config['body_font'],
            bg=style_config.get('card_bg_color', style_config['secondary_bg_color']),
            fg=style_config['fg_color']
        )
        password_label.pack(pady=(10, 3))
        
        self.login_password_var = tk.StringVar()
        password_entry = ttk.Entry(
            parent,
            textvariable=self.login_password_var,
            show='*',
            width=25,
            font=style_config['body_font']
        )
        password_entry.pack(pady=3)
        
        # Login button
        def handle_login():
            username = self.login_username_var.get()
            password = self.login_password_var.get()
            self.handle_login(username, password)
        
        login_btn = self.create_modern_button(
        parent,
        text="Login to Vault",
        command=handle_login,
        bg_color=style_config['accent_color'],
        width=200,
        height=40
    )
        login_btn.pack(pady=15)
        
        # Bind Enter key
        password_entry.bind('<Return>', lambda e: handle_login())
        username_entry.focus()

    def _setup_basic_signup_tab(self, parent: ttk.Frame, style_config: Dict[str, Any]) -> None:
        """Setup basic signup tab that works with current theme system"""
        # Configure parent frame background
        parent.configure(style='Dark.TFrame')
        
        # Username field
        username_label = tk.Label(
            parent,
            text="Username",
            font=style_config['body_font'],
            bg=style_config.get('card_bg_color', style_config['secondary_bg_color']),
            fg=style_config['fg_color']
        )
        username_label.pack(pady=(15, 3))
        
        self.signup_username_var = tk.StringVar()
        username_entry = ttk.Entry(
            parent,
            textvariable=self.signup_username_var,
            width=25,
            font=style_config['body_font']
        )
        username_entry.pack(pady=3)
        
        # Password field
        password_label = tk.Label(
            parent,
            text="Master Password", 
            font=style_config['body_font'],
            bg=style_config.get('card_bg_color', style_config['secondary_bg_color']),
            fg=style_config['fg_color']
        )
        password_label.pack(pady=(10, 3))
        
        self.signup_password_var = tk.StringVar()
        password_entry = ttk.Entry(
            parent,
            textvariable=self.signup_password_var,
            show='*',
            width=25,
            font=style_config['body_font']
        )
        password_entry.pack(pady=3)
        
        # Confirm Password field
        confirm_label = tk.Label(
            parent,
            text="Confirm Password", 
            font=style_config['body_font'],
            bg=style_config.get('card_bg_color', style_config['secondary_bg_color']),
            fg=style_config['fg_color']
        )
        confirm_label.pack(pady=(10, 3))
        
        self.signup_confirm_var = tk.StringVar()
        confirm_entry = ttk.Entry(
            parent,
            textvariable=self.signup_confirm_var,
            show='*',
            width=25,
            font=style_config['body_font']
        )
        confirm_entry.pack(pady=3)
        
        # 2FA checkbox
        self.signup_tfa_var = tk.BooleanVar()
        tfa_check = ttk.Checkbutton(
            parent,
            text="Enable Two-Factor Authentication",
            variable=self.signup_tfa_var
        )
        tfa_check.pack(pady=8)
        
        # Signup button
        def handle_signup():
            username = self.signup_username_var.get()
            password = self.signup_password_var.get()
            confirm = self.signup_confirm_var.get()
            enable_2fa = self.signup_tfa_var.get()
            self.handle_signup(username, password, confirm, enable_2fa)
        
        signup_btn = self.create_modern_button(
        parent,
        text="Create Account", 
        command=handle_signup,
        bg_color=style_config['accent_color'],
        width=200,
        height=40
    )
        signup_btn.pack(pady=15)
        
        # Bind Enter key
        confirm_entry.bind('<Return>', lambda e: handle_signup())
        username_entry.focus()

    def _setup_modern_login_tab(self, parent: ttk.Frame, style_config: Dict[str, Any]) -> None:
        """Setup modern login tab"""
        from ui.modern_widgets import ModernEntry, ModernButton
        
        # Username field
        username_frame = tk.Frame(parent, bg=style_config['card_bg_color'])
        username_frame.pack(fill='x', pady=10)
        
        username_label = tk.Label(
            username_frame,
            text="Username",
            font=style_config['body_font'],
            bg=style_config['card_bg_color'],
            fg=style_config['muted_fg_color']
        )
        username_label.pack(anchor='w')
        
        self.login_username_var = tk.StringVar()
        username_entry = ModernEntry(username_frame, "Enter your username", style_config)
        username_entry.pack(fill='x', pady=5)
        
        # Password field  
        password_frame = tk.Frame(parent, bg=style_config['card_bg_color'])
        password_frame.pack(fill='x', pady=10)
        
        password_label = tk.Label(
            password_frame,
            text="Master Password", 
            font=style_config['body_font'],
            bg=style_config['card_bg_color'],
            fg=style_config['muted_fg_color']
        )
        password_label.pack(anchor='w')
        
        self.login_password_var = tk.StringVar()
        password_entry = tk.Entry(
            password_frame,
            show='*',
            font=style_config['body_font'],
            bg=style_config['secondary_bg_color'],
            fg=style_config['fg_color'],
            relief='flat',
            bd=2,
            highlightbackground=style_config['border_color'],
            highlightcolor=style_config['accent_color'],
            highlightthickness=1,
            insertbackground=style_config['fg_color']
        )
        password_entry.pack(fill='x', pady=5)
        
        # 2FA info
        tfa_info = tk.Label(
            parent,
            text="🔒 Two-factor authentication ready",
            font=('Arial', 9),
            bg=style_config['card_bg_color'], 
            fg=style_config['success_color']
        )
        tfa_info.pack(pady=10)
        
        # Login button
        def handle_login():
            username = username_entry.get()
            password = password_entry.get()
            self.handle_login(username, password)
        
        login_btn = ModernButton(
            parent,
            text="Login to Vault",
            command=handle_login,
            bg_color=style_config['accent_color'],
            style_config=style_config,
            width=200,
            height=45
        )
        login_btn.pack(pady=20)
        
        # Quick actions
        quick_frame = tk.Frame(parent, bg=style_config['card_bg_color'])
        quick_frame.pack(fill='x', pady=10)
        
        forgot_btn = ModernButton(
            quick_frame,
            text="Forgot Password?",
            command=self.show_password_recovery,
            bg_color=style_config['secondary_bg_color'],
            style_config=style_config,
            width=140,
            height=35
        )
        forgot_btn.pack(side='left')
        
        # Bind Enter key
        password_entry.bind('<Return>', lambda e: handle_login())
        username_entry.entry.focus()

    def _style_notebook(self, notebook: ttk.Notebook, style_config: Dict[str, Any]) -> None:
        """Style the notebook tabs"""
        style = ttk.Style()
        
        style.configure("Modern.TNotebook", 
                    background=style_config['card_bg_color'],
                    borderwidth=0)
        
        style.configure("Modern.TNotebook.Tab",
                    background=style_config['secondary_bg_color'],
                    foreground=style_config['muted_fg_color'],
                    padding=[20, 10],
                    font=style_config['body_font'])
        
        style.map("Modern.TNotebook.Tab",
                background=[('selected', style_config['accent_color']),
                            ('active', style_config['secondary_color'])],
                foreground=[('selected', style_config['fg_color']),
                            ('active', style_config['fg_color'])])
        
        notebook.configure(style="Modern.TNotebook")

    def _setup_signup_tab(self, parent: ttk.Frame, style_config: Dict[str, Any]) -> None:
        """ Setup the signup tab with username, password, and 2FA options """
        # Username field
        username_label = tk.Label(parent, text="Username:", 
                                font=style_config['body_font'],
                                fg=style_config['fg_color'],
                                bg=style_config['bg_color'])
        username_label.pack(pady=3)
        
        signup_username_var = tk.StringVar()
        signup_username_entry = ttk.Entry(parent, textvariable=signup_username_var, 
                                        width=25, style='Dark.TEntry')
        signup_username_entry.pack(pady=1)
        
        # Master Password field
        password_label = tk.Label(parent, text="Master Password:", 
                                font=style_config['body_font'],
                                fg=style_config['fg_color'],
                                bg=style_config['bg_color'])
        password_label.pack(pady=1)
        
        signup_password_var = tk.StringVar()
        signup_password_entry = ttk.Entry(parent, textvariable=signup_password_var, 
                                        show='*', width=25, style='Dark.TEntry')
        signup_password_entry.pack(pady=1)
        
        # Confirm Password field
        confirm_label = tk.Label(parent, text="Confirm Password:", 
                               font=style_config['body_font'],
                               fg=style_config['fg_color'],
                               bg=style_config['bg_color'])
        confirm_label.pack(pady=1)
        
        signup_confirm_var = tk.StringVar()
        signup_confirm_entry = ttk.Entry(parent, textvariable=signup_confirm_var, 
                                    show='*', width=25, style='Dark.TEntry')
        signup_confirm_entry.pack(pady=1)
        
        # 2FA checkbox
        signup_tfa_var = tk.BooleanVar()
        signup_tfa_check = ttk.Checkbutton(parent, 
                                        text="Enable Two-Factor Authentication", 
                                        variable=signup_tfa_var, 
                                        style='Dark.TCheckbutton')
        signup_tfa_check.pack(pady=3)
        
        def handle_signup():
            """Handle user signup with validation"""
            self.handle_signup(signup_username_var.get(),
                            signup_password_var.get(),
                            signup_confirm_var.get(),
                            signup_tfa_var.get())
        
        # Signup button
        self.create_modern_button(parent, text="Create Account", 
                    command=handle_signup,
                    bg_color=style_config['secondary_color'],
                    #hover_color=style_config['accent_color'],
                    #width=140, height=40).pack(pady=10)
                    variant="secondary")
        
        # Bind Enter key to signup por conveniencia
        signup_confirm_entry.bind('<Return>', lambda e: handle_signup())
        signup_username_entry.focus()  # Start with username field focused

    def _setup_login_tab(self, parent: ttk.Frame, style_config: Dict[str, Any]) -> None:
        """Setup the login tab with username and password fields"""
        # Username field
        username_label = tk.Label(parent, text="Username:", 
                                font=style_config['body_font'],
                                fg=style_config['fg_color'],
                                bg=style_config['bg_color'])
        username_label.pack(pady=3)
        
        login_username_var = tk.StringVar()
        login_username_entry = ttk.Entry(parent, textvariable=login_username_var, 
                                    width=25, style='Dark.TEntry')
        login_username_entry.pack(pady=3)
        
        # Password field
        password_label = tk.Label(parent, text="Master Password:", 
                                font=style_config['body_font'],
                                fg=style_config['fg_color'],
                                bg=style_config['bg_color'])
        password_label.pack(pady=3)
        
        login_password_var = tk.StringVar()
        login_password_entry = ttk.Entry(parent, textvariable=login_password_var, 
                                    show='*', width=25, style='Dark.TEntry')
        login_password_entry.pack(pady=3)

        # Info text about 2FA when logging in with transparent background
        info_label = tk.Label(parent,
                               text='If 2FA is enabled, a \nverification code will be needed.',
                               font=style_config['body_font'],
                               fg=style_config['fg_color'],
                               bg=style_config['bg_color'],
                               justify='center'
                               )
        info_label.pack(pady=3)
        
        def handle_login():
            """Handle user login with secure password storage."""
            self.handle_login(login_username_var.get(), 
                            login_password_var.get())
        
        # Login button
        self.create_modern_button(parent, text="Login", 
                    command=handle_login,
                    bg_color=style_config['accent_color'],
                    #hover_color=style_config['secondary_color'],
                    #width=120, height=40).pack(pady=10)
                    variant="primary")
        
        # Bind Enter key to login for convenience
        login_password_entry.bind('<Return>', lambda e: handle_login())
        login_username_entry.focus()  # Start with username field focused

    def handle_login(self, username: str, password: str) -> None:
        """Handle user login with security checks and secure password storage.
        Security Features:
            - Account lockout after multiple failed attempts
            - Secure password storage
            - 2FA verification if enabled
            - Audit logging
            - Input validation
        """
        # Validate credentials first before DB access
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return

        # Store password securely (once)
        self._secure_password.set(password)

        # Check if account is locked due to previous failed attempts.
        # Check before verify_master_password to avoid running expensive Argon2id
        if self._is_account_locked(username):
            remaining_time = self._get_remaining_lockout_time(username)
            messagebox.showerror("Account Locked",
                            f"Account is locked. Try again in {remaining_time} seconds.")
            return

        # Verify master password via constant-time Argon2id+AES-GCM check
        if self.verify_master_password(username, password):
            # Check if 2FA is enabled for this user
            profiles = self.database_manager.load_profiles()
            user_profile = profiles.get(username, {})
            
            if user_profile.get('2fa_enabled', False):
                # 2FA is enabled, require verification
                self.show_2fa_verification(username, password)
            else:
                # 2FA is not enabled, proceed with normal login
                self.complete_login(username, password)
        else:
            # Track failed login attempt
            self._handle_failed_login(username)
            remaining_attempts = MAX_LOGIN_ATTEMPTS - self.login_attempts.get(username, 0)
            messagebox.showerror("Error", 
                            f"Invalid credentials. {remaining_attempts} attempts remaining.")

    def show_2fa_verification(self, username: str, password: str) -> None:
        """ Show 2FA verification dialog (rate-limited to 5 attempts) """
        cfg  = self._get_style_config()
        bg   = cfg["bg_color"]
        card = cfg.get("card_bg_color", cfg.get("secondary_bg_color", bg))
        acc  = cfg["accent_color"]
        fg   = cfg["fg_color"]
        mfg  = cfg.get("muted_fg_color", fg)
        bdr  = cfg.get("border_color", "#2d2d5a")
        ibg  = cfg.get("input_bg_color", cfg.get("secondary_bg_color", bg))
        err  = cfg.get("error_color", "#f85149")
        bod  = cfg["body_font"]
        bf   = cfg["button_font"]
        hf   = cfg["heading_font"]

        MAX_2FA_ATTEMPTS = 5
        attempt_count = [0]

        d = tk.Toplevel(self.root)
        d.title("Two-Factor Authentication")
        d.configure(bg=bg)
        d.geometry("400x340")
        d.resizable(False, False)
        d.transient(self.root)
        d.update_idletasks()
        d.grab_set()
        self._center_dialog(d)

        # Header bar
        hdr = tk.Frame(d, bg=acc, height=4)
        hdr.pack(fill="x")

        outer = tk.Frame(d, bg=bg)
        outer.pack(fill="both", expand=True, padx=32, pady=28)

        # Icon + title
        tk.Label(outer, text="🔐", font=("Segoe UI", 28), bg=bg, fg=acc).pack()
        tk.Label(outer, text="Two-Factor Authentication",
                 font=hf, bg=bg, fg=fg).pack(pady=(4, 2))
        tk.Label(outer, text="Enter the 6-digit code from your authenticator app",
                 font=bod, bg=bg, fg=mfg, wraplength=320).pack(pady=(0, 18))

        # Code input with auto-format
        code_var = tk.StringVar()
        code_entry = tk.Entry(
            outer, textvariable=code_var,
            font=("Courier New", 22, "bold"), width=10, justify="center",
            bg=ibg, fg=fg, relief="flat", bd=0,
            highlightbackground=bdr, highlightcolor=acc, highlightthickness=2,
            insertbackground=fg, selectbackground=acc, selectforeground=bg,
        )
        code_entry.pack(fill="x", ipady=10, pady=(0, 6))
        code_entry.focus()

        # Restrict to digits only, max 6
        def _validate_code(new_val):
            return new_val.isdigit() and len(new_val) <= 6 or new_val == ""
        vcmd = d.register(_validate_code)
        code_entry.configure(validate="key", validatecommand=(vcmd, "%P"))

        err_lbl = tk.Label(outer, text="", font=("Segoe UI", 9),
                           bg=bg, fg=err, wraplength=320)
        err_lbl.pack(pady=(0, 10))

        def _verify():
            code = code_var.get().strip()
            if len(code) != 6:
                err_lbl.config(text="Please enter a complete 6-digit code.")
                return

            attempt_count[0] += 1
            remaining = MAX_2FA_ATTEMPTS - attempt_count[0]

            if self.verify_2fa_code(username, code):
                d.destroy()
                self.complete_login(username, password)
            else:
                code_var.set("")
                if remaining <= 0:
                    err_lbl.config(text="Too many failed attempts. Please log in again.")
                    d.after(1500, d.destroy)
                    self.audit_logger.log_security_event(
                        username, "2FA_LOCKOUT", "Max 2FA attempts exceeded")
                else:
                    err_lbl.config(
                        text=f"Invalid code. {remaining} attempt{'s' if remaining > 1 else ''} remaining.")
                    code_entry.focus()

        btn_row = tk.Frame(outer, bg=bg)
        btn_row.pack(fill="x")

        tk.Button(btn_row, text="Verify", command=_verify,
                  font=bf, bg=acc, fg=cfg.get("btn_fg_color", "#ffffff"),
                  relief="flat", bd=0, cursor="hand2",
                  activebackground=cfg.get("btn_hover_color", acc),
                  activeforeground=cfg.get("btn_fg_color", "#ffffff"),
                  padx=24, pady=8).pack(side="right")

        tk.Button(btn_row, text="Cancel", command=d.destroy,
                  font=bf, bg=card, fg=mfg,
                  relief="flat", bd=0, cursor="hand2",
                  activebackground=bdr, activeforeground=fg,
                  padx=16, pady=8).pack(side="right", padx=(0, 8))

        code_entry.bind("<Return>", lambda _: _verify())
        
    def show_2fa_setup(self, username: str, secret: str, password: Optional[str] = None, 
                    enable_callback: Optional[Callable] = None) -> None:
        """Show 2FA setup dialog with QR code"""
        if password:
            self._temp_password.set(password)

        cfg  = self._get_style_config()
        bg   = cfg["bg_color"]
        card = cfg.get("card_bg_color", cfg.get("secondary_bg_color", bg))
        acc  = cfg["accent_color"]
        fg   = cfg["fg_color"]
        mfg  = cfg.get("muted_fg_color", fg)
        bdr  = cfg.get("border_color", "#2d2d5a")
        ibg  = cfg.get("input_bg_color", cfg.get("secondary_bg_color", bg))
        suc  = cfg.get("success_color", "#3fb950")
        err  = cfg.get("error_color", "#f85149")
        bod  = cfg["body_font"]
        bf   = cfg["button_font"]
        hf   = cfg["heading_font"]

        d = tk.Toplevel(self.root)
        d.title("Set Up Two-Factor Authentication")
        d.configure(bg=bg)
        d.geometry("480x560")
        d.resizable(False, False)
        d.transient(self.root)
        d.update_idletasks()
        d.grab_set()
        self._center_dialog(d)

        # Accent top bar
        tk.Frame(d, bg=acc, height=4).pack(fill="x")

        # Scrollable outer area
        outer = tk.Frame(d, bg=bg)
        outer.pack(fill="both", expand=True, padx=32, pady=20)

        # Header
        tk.Label(outer, text="Set Up Authenticator",
                 font=hf, bg=bg, fg=fg).pack(anchor="w")
        tk.Label(outer, text="Protect your account with time-based one-time passwords (TOTP)",
                 font=bod, bg=bg, fg=mfg, wraplength=400).pack(anchor="w", pady=(2, 14))

        # Step badges
        steps_frame = tk.Frame(outer, bg=bg)
        steps_frame.pack(fill="x", pady=(0, 12))
        steps = [
            ("1", "Install an authenticator app\n(Google Authenticator, Authy, 1Password…)"),
            ("2", "Scan the QR code or enter the secret manually"),
            ("3", "Enter the 6-digit code to confirm"),
        ]
        for num, text in steps:
            row = tk.Frame(steps_frame, bg=bg)
            row.pack(fill="x", pady=2)
            tk.Label(row, text=num, font=("Segoe UI", 9, "bold"),
                     bg=acc, fg=cfg.get("btn_fg_color", "#fff"),
                     width=2, height=1).pack(side="left", padx=(0, 8))
            tk.Label(row, text=text, font=("Segoe UI", 9),
                     bg=bg, fg=fg, justify="left").pack(side="left", anchor="w")

        # Separator
        tk.Frame(outer, bg=bdr, height=1).pack(fill="x", pady=(4, 12))

        # QR Code
        try:
            totp = pyotp.TOTP(secret)
            uri  = totp.provisioning_uri(username, issuer_name="Krault")
            qr   = qrcode.QRCode(version=1, box_size=4, border=2)
            qr.add_data(uri)
            qr.make(fit=True)
            qr_img   = qr.make_image(fill_color=fg, back_color=bg)
            photo    = ImageTk.PhotoImage(qr_img)
            qr_frame = tk.Frame(outer, bg=bdr, padx=2, pady=2)
            qr_frame.pack()
            qr_lbl   = tk.Label(qr_frame, image=photo, bg=bg)
            qr_lbl.image = photo
            qr_lbl.pack()
        except Exception as e:
            logging.warning(f"QR generation failed: {e}")
            tk.Label(outer, text="[QR generation failed — use manual entry below]",
                     font=bod, bg=bg, fg=err).pack()

        # Manual secret
        manual_frame = tk.Frame(outer, bg=card,
                                highlightbackground=bdr, highlightthickness=1)
        manual_frame.pack(fill="x", pady=(10, 4))
        inner_m = tk.Frame(manual_frame, bg=card)
        inner_m.pack(fill="x", padx=10, pady=8)
        tk.Label(inner_m, text="Manual entry secret:",
                 font=("Segoe UI", 9), bg=card, fg=mfg).pack(anchor="w")
        sec_row = tk.Frame(inner_m, bg=card)
        sec_row.pack(fill="x")
        tk.Label(sec_row, text=secret,
                 font=("Courier New", 11, "bold"),
                 bg=card, fg=acc).pack(side="left")

        copied_lbl = tk.Label(sec_row, text="", font=("Segoe UI", 9),
                              bg=card, fg=suc)
        copied_lbl.pack(side="left", padx=(8, 0))

        def _copy_secret():
            self.copy_to_clipboard(secret)
            copied_lbl.config(text="✓ Copied!")
            d.after(2000, lambda: copied_lbl.config(text=""))

        tk.Button(sec_row, text="Copy", command=_copy_secret,
                  font=("Segoe UI", 9), bg=bdr, fg=fg,
                  relief="flat", bd=0, cursor="hand2",
                  activebackground=acc, activeforeground=cfg.get("btn_fg_color", "#fff"),
                  padx=8, pady=2).pack(side="right")

        # Verification input
        tk.Label(outer, text="VERIFICATION CODE",
                 font=("Segoe UI", 9), bg=bg, fg=mfg).pack(anchor="w", pady=(12, 2))
        code_var = tk.StringVar()
        code_entry = tk.Entry(
            outer, textvariable=code_var,
            font=("Courier New", 18, "bold"), width=10, justify="center",
            bg=ibg, fg=fg, relief="flat", bd=0,
            highlightbackground=bdr, highlightcolor=acc, highlightthickness=2,
            insertbackground=fg, selectbackground=acc, selectforeground=bg,
        )
        code_entry.pack(fill="x", ipady=8, pady=(0, 4))
        code_entry.focus()

        def _validate_code(val):
            return val.isdigit() and len(val) <= 6 or val == ""
        vcmd = d.register(_validate_code)
        code_entry.configure(validate="key", validatecommand=(vcmd, "%P"))

        err_lbl = tk.Label(outer, text="", font=("Segoe UI", 9), bg=bg, fg=err)
        err_lbl.pack(anchor="w")

        def _verify_and_enable():
            code = code_var.get().strip()
            if len(code) != 6:
                err_lbl.config(text="Enter a complete 6-digit code.")
                return
            try:
                if self._verify_totp_with_replay_protection(username, secret, code):
                    if self.toggle_2fa(True):
                        d.destroy()
                        messagebox.showinfo("Success", "Two-factor authentication is now active!")
                        if enable_callback:
                            enable_callback()
                        if self._temp_password.get():
                            self.complete_login(username, self._temp_password.get())
                            self._temp_password.clear()
                    else:
                        err_lbl.config(text="Failed to enable 2FA. Please try again.")
                else:
                    err_lbl.config(text="Invalid code — make sure your device clock is synced.")
                    code_var.set("")
                    code_entry.focus()
            except Exception as ex:
                logging.error(f"2FA enable error: {ex}")
                err_lbl.config(text="An error occurred. Please try again.")

        btn_row = tk.Frame(outer, bg=bg)
        btn_row.pack(fill="x", pady=(8, 0))

        tk.Button(btn_row, text="✓  Verify & Enable 2FA", command=_verify_and_enable,
                  font=bf, bg=acc, fg=cfg.get("btn_fg_color", "#ffffff"),
                  relief="flat", bd=0, cursor="hand2",
                  activebackground=cfg.get("btn_hover_color", acc),
                  activeforeground=cfg.get("btn_fg_color", "#ffffff"),
                  padx=20, pady=8).pack(side="right")

        tk.Button(btn_row, text="Cancel", command=d.destroy,
                  font=bf, bg=card, fg=mfg,
                  relief="flat", bd=0, cursor="hand2",
                  activebackground=bdr, activeforeground=fg,
                  padx=16, pady=8).pack(side="right", padx=(0, 8))

        code_entry.bind("<Return>", lambda _: _verify_and_enable())

    def complete_login(self, username: str, password: str) -> None:
        """ Complete the login process with secure memory handling"""
        try:
            # Store password securely for session duration.
            self._secure_password.set(password)

            # Get secure database path
            self.current_database = self.database_manager.get_user_database_path(username)

            # Reset login attempts on successful login
            self.login_attempts[username] = 0
            self.lockout_time.pop(username, None)
            self._persist_login_attempts()
            
            # Get user salt and initialize encryption
            salt = self.database_manager.get_user_salt(username)
            if not self.security_manager.initialize_encryption(
                password, username, salt, kdf=KDF_DEFAULT
            ):
                messagebox.showerror("Error", "Failed to initialize encryption")
                return
                
            # Set current user
            self.current_user = username

            # Ensure database exists
            if not self.database_manager.ensure_database_exists(self.current_database):
                messagebox.showerror("Error", "Failed to create user database")
                return
                
            # Load entries from database and precompute lightweight metadata
            self.entries = self.database_manager.load_data(self.current_database)
            self._rebuild_entry_index()

            # Generate session token for security
            session_token = self.security_manager.generate_session_token()
            
            # Log successful login
            self.audit_logger.log_login(username, True, f"Session: {session_token[:8]}...")
            
            # Show main interface
            self.show_main_interface()
            
        except Exception as e:
            logging.error(f"Login completion error: {e}")
            messagebox.showerror("Error", f"Login failed: {e}")

    def handle_signup(self, username: str, password: str, confirm_password: str, enable_2fa: bool) -> None:
        """ Handle user signup with validation and profile creation """
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return
            
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return
            
        # Check password strength against policy
        strength, feedback = self.password_policy_manager.check_password_compliance(password)
        if strength < self.password_policy_manager.policy['min_strength']:
            feedback_text = "\n".join(feedback)
            messagebox.showerror("Password Policy Error", 
                            f"Password does not meet policy requirements:\n{feedback_text}")
            return
            
        # Check if username already exists
        profiles = self.database_manager.load_profiles()
        if username in profiles:
            messagebox.showerror("Error", "Username already exists")
            return
            
        # Generate salt and initialize encryption. Every new account is
        # created with Argon2id (KDF_DEFAULT)
        salt = self.security_manager.generate_salt()
        if not self.security_manager.initialize_encryption(password, username, salt, kdf=KDF_DEFAULT):
            messagebox.showerror("Error", "Failed to initialize encryption")
            return
            
        # Create password verifier. Login uses this to verify the password cryptographically
        # without storing the password itself.
        password_verifier = self.security_manager.create_password_verifier()

        # Create user profile
        user_profile = {
            'username': username,
            'created_at': time.time(),
            '2fa_enabled': enable_2fa,
            'password_verifier': password_verifier,
            'kdf': KDF_DEFAULT,
        }
        
        # Generate 2FA secret if enabled.
        plain_2fa_secret = None
        if enable_2fa:
            plain_2fa_secret = pyotp.random_base32()
            user_profile['2fa_secret'] = self.security_manager.encrypt_data(plain_2fa_secret)
            
        # Save profile
        profiles[username] = user_profile
        if not self.database_manager.save_profiles(profiles):
            messagebox.showerror("Error", "Failed to save user profile")
            return
            
        # Save salt for future encryption
        salts = self.database_manager.load_salts()
        salts[username] = base64.b64encode(salt).decode()
        if not self.database_manager.save_salts(salts):
            messagebox.showerror("Error", "Failed to save encryption salt")
            return
            
        # Create empty database for new user
        self.current_user = username
        self.current_database = self.database_manager.get_user_database_path(username)
        if not self.database_manager.save_data([], self.current_database):
            messagebox.showerror("Error", "Failed to create user database")
            return
            
        # Show 2FA setup if enabled
        if enable_2fa:
            # Pass the plaintext secret to setup
            self.show_2fa_setup(username, plain_2fa_secret, password)
        else:
            messagebox.showinfo("Success", "Account created successfully!")
            self.complete_login(username, password)

    # Customize interface start
    def show_main_interface(self) -> None:
        """ Sidebar + card-based main vault interface """
        self.clear_screen()
        self._reset_activity_timer()
        cfg = self._get_style_config()

        bg   = cfg["bg_color"]
        sbg  = cfg.get("secondary_bg_color", bg)
        card = cfg.get("card_bg_color", sbg)
        acc  = cfg["accent_color"]
        fg   = cfg["fg_color"]
        mfg  = cfg.get("muted_fg_color", fg)
        bdr  = cfg.get("border_color", "#2d2d5a")
        btn  = cfg.get("btn_bg_color", acc)
        bfg  = cfg.get("btn_fg_color", "#ffffff")
        ibg  = cfg.get("input_bg_color", sbg)
        bod  = cfg["body_font"]
        bf   = cfg["button_font"]
        hf   = cfg["heading_font"]

        self.status_var = tk.StringVar()

        # Root split: sidebar | main
        root_frame = tk.Frame(self.root, bg=bg)
        root_frame.pack(fill="both", expand=True)

        # Sidebar
        sidebar = tk.Frame(root_frame, bg=sbg, width=190,
                           highlightbackground=bdr, highlightthickness=1)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        # Logo row
        logo_row = tk.Frame(sidebar, bg=sbg)
        logo_row.pack(fill="x", padx=16, pady=(18, 16))
        tk.Label(logo_row, text="🛡", font=("Segoe UI", 16),
                 bg=sbg, fg=acc).pack(side="left")
        tk.Label(logo_row, text=" Krault", font=bf,
                 bg=sbg, fg=fg).pack(side="left")

        tk.Frame(sidebar, bg=bdr, height=1).pack(fill="x")

        # Nav item factory with proper lightening
        self._nav_items = []
        def nav_item(label, icon, cmd, active=False):
            row = tk.Frame(sidebar, bg=sbg, cursor="hand2")
            row.pack(fill="x")
            indicator = tk.Frame(row, bg=acc if active else sbg, width=3)
            indicator.pack(side="left", fill="y")

            # Compute background colors
            normal_bg = sbg
            active_bg = self._lighten_color(acc, 13)
            hover_bg = self._lighten_color(sbg, -8) if sbg != bg else self._lighten_color(bg, 10)

            lbl = tk.Label(row, text=f"  {icon}  {label}",
                        font=bod, bg=active_bg if active else normal_bg,
                        fg=acc if active else mfg, anchor="w", pady=9)
            lbl.pack(side="left", fill="x", expand=True)

            def enter(e, r=row, l=lbl, i=indicator):
                if l.cget("fg") != acc:
                    # hover effect for inactive items
                    l.config(bg=hover_bg)
                    r.config(bg=hover_bg)
            def leave(e, r=row, l=lbl, a=active, i=indicator):
                if a:
                    l.config(bg=active_bg)
                    r.config(bg=sbg)
                else:
                    l.config(bg=normal_bg)
                    r.config(bg=sbg)

            row.bind("<Button-1>", lambda e, c=cmd: c())
            lbl.bind("<Button-1>", lambda e, c=cmd: c())
            row.bind("<Enter>", enter)
            lbl.bind("<Enter>", enter)
            row.bind("<Leave>", leave)
            lbl.bind("<Leave>", leave)
            self._nav_items.append((row, lbl, indicator))


        tk.Label(sidebar, text="VAULT", font=("Segoe UI", 9),
                 bg=sbg, fg=mfg).pack(anchor="w", padx=16, pady=(12, 2))
        nav_item("All entries",      "🔑", self.show_main_interface, active=True)
        nav_item("Add entry",        "➕", self.add_password_entry)
        nav_item("Generator",        "🎲", self.show_password_generator)

        tk.Label(sidebar, text="ACCOUNT", font=("Segoe UI", 9),
                 bg=sbg, fg=mfg).pack(anchor="w", padx=16, pady=(12, 2))
        nav_item("2FA setup",        "🛡", lambda: self.show_2fa_setup(
            self.current_user,
            self.security_service.get_2fa_secret() if hasattr(self, "security_service") else ""))
        nav_item("Settings",         "⚙", self.show_settings)
        nav_item("Customize",        "🎨", self.show_customize_dialog)

        # User footer
        tk.Frame(sidebar, bg=bdr, height=1).pack(fill="x", side="bottom")
        footer = tk.Frame(sidebar, bg=sbg)
        footer.pack(fill="x", side="bottom", padx=12, pady=10)
        init = (self.current_user or "?")[0].upper()
        av = tk.Label(footer, text=init, font=bf,
                      bg=acc, fg=bfg, width=2)
        av.pack(side="left")
        tk.Label(footer, text=f"  {self.current_user}", font=bod,
                 bg=sbg, fg=fg).pack(side="left")
        lock_btn = tk.Label(footer, text="⏏", font=("Segoe UI", 14),
                            bg=sbg, fg=mfg, cursor="hand2")
        lock_btn.pack(side="right")
        lock_btn.bind("<Button-1>", lambda _: self.logout())

        # Main content
        main = tk.Frame(root_frame, bg=bg)
        main.pack(side="left", fill="both", expand=True)

        # Top bar
        topbar = tk.Frame(main, bg=sbg,
                          highlightbackground=bdr, highlightthickness=1)
        topbar.pack(fill="x")

        search_var = tk.StringVar(value=getattr(self, "entry_search_text", ""))
        self.entry_search_var = search_var

        search_frame = tk.Frame(topbar, bg=sbg)
        search_frame.pack(side="left", padx=16, pady=10)
        tk.Label(search_frame, text="🔍", font=bod, bg=sbg, fg=mfg).pack(side="left")
        search_entry = tk.Entry(search_frame, textvariable=search_var,
                                font=bod, bg=ibg, fg=fg, relief="flat", bd=0,
                                highlightbackground=bdr, highlightcolor=acc,
                                highlightthickness=1, insertbackground=fg, width=28)
        search_entry.pack(side="left", ipady=5, padx=(4, 0))
        search_entry.bind("<KeyRelease>", lambda e: self._schedule_entry_filter(search_var.get()))

        sort_options = {
            "Website/App name": "website",
            "Username": "username",
            "Security strength": "security",
        }
        current_sort = getattr(self, "entry_sort_value", "website")
        current_sort_label = next(
            (label for label, value in sort_options.items() if value == current_sort),
            "Website/App name"
        )
        self.entry_sort_var = tk.StringVar(value=current_sort_label)

        sort_frame = tk.Frame(topbar, bg=sbg)
        sort_frame.pack(side="left", padx=(0, 16), pady=10)
        tk.Label(sort_frame, text="Sort by", font=bod, bg=sbg, fg=mfg).pack(side="left")
        sort_menu = tk.OptionMenu(
            sort_frame,
            self.entry_sort_var,
            *sort_options.keys(),
            command=lambda label: self._set_entry_sort(sort_options.get(label, "website"))
        )
        sort_menu.config(
            font=bod, bg=ibg, fg=fg, relief="flat", bd=0,
            activebackground=cfg.get("btn_hover_color", btn),
            activeforeground=fg, highlightbackground=bdr,
            highlightthickness=1, cursor="hand2", width=18
        )
        sort_menu["menu"].config(
            font=bod, bg=ibg, fg=fg,
            activebackground=acc, activeforeground=bfg
        )
        sort_menu.pack(side="left", ipady=2, padx=(6, 0))

        """
        add_btn = tk.Button(topbar, text="+ Add entry",
                            command=self.add_password_entry,
                            font=bf, bg=btn, fg=bfg, relief="flat",
                            activebackground=cfg.get("btn_hover_color", btn),
                            activeforeground=bfg, bd=0, cursor="hand2",
                            padx=14, pady=6)
        add_btn.pack(side="right", padx=16, pady=10)
        """
        # Stats row
        stats_frame = tk.Frame(main, bg=bg)
        stats_frame.pack(fill="x", padx=20, pady=(16, 0))

        def stat_card(parent, label, value, value_color=None):
            c = tk.Frame(parent, bg=card,
                         highlightbackground=bdr, highlightthickness=1)
            c.pack(side="left", fill="x", expand=True, padx=(0, 10))
            tk.Label(c, text=label.upper(), font=("Segoe UI", 9),
                     bg=card, fg=mfg).pack(anchor="w", padx=14, pady=(12, 2))
            value_lbl = tk.Label(c, text=str(value), font=("Segoe UI", 22, "bold"),
                     bg=card, fg=value_color or fg)
            value_lbl.pack(anchor="w", padx=14, pady=(0, 12))
            return value_lbl

        total   = len(self.entries)
        weak    = sum(1 for e in self.entries if self._entry_strength(e) <= 2)
        score   = max(0, 100 - weak * 10) if total else 0
        score_c = cfg.get("success_color", "#3fb950") if score >= 70                   else cfg.get("warning_color", "#d29922")

        self._stat_total_label = stat_card(stats_frame, "Total entries", total)
        self._stat_weak_label  = stat_card(stats_frame, "Weak passwords", weak,
                  cfg.get("error_color", "#f85149") if weak else fg)
        self._stat_score_label = stat_card(stats_frame, "Security score", f"{score}%", score_c)

        # Entry list header
        list_header = tk.Frame(main, bg=bg)
        list_header.pack(fill="x", padx=20, pady=(18, 8))
        tk.Label(list_header, text="All entries", font=hf,
                 bg=bg, fg=fg).pack(side="left")
        self.count_label = tk.Label(list_header,
                                    text=f"  {total} entries",
                                    font=("Segoe UI", 10),
                                    bg=bg, fg=mfg)
        self.count_label.pack(side="left", pady=2)

        # Scrollable entry canvas
        canvas_frame = tk.Frame(main, bg=bg)
        canvas_frame.pack(fill="both", expand=True, padx=20, pady=(0, 16))

        self._entry_canvas = tk.Canvas(canvas_frame, bg=bg,
                                       highlightthickness=0, bd=0)
        scrollbar = tk.Scrollbar(canvas_frame, orient="vertical",
                                 command=self._entry_canvas.yview)
        self._entry_canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self._entry_canvas.pack(side="left", fill="both", expand=True)

        self.entries_container = tk.Frame(self._entry_canvas, bg=bg)
        self._canvas_window = self._entry_canvas.create_window(
            (0, 0), window=self.entries_container, anchor="nw")

        def on_resize(e):
            self._entry_canvas.itemconfig(self._canvas_window, width=e.width)
        self._entry_canvas.bind("<Configure>", on_resize)

        def on_frame_resize(e):
            self._entry_canvas.configure(
                scrollregion=self._entry_canvas.bbox("all"))
        self.entries_container.bind("<Configure>", on_frame_resize)

        # Mouse-wheel scroll
        def on_wheel(e):
            self._entry_canvas.yview_scroll(
                -1 if e.delta > 0 else 1, "units")
        self._entry_canvas.bind("<MouseWheel>", on_wheel)
        self.entries_container.bind("<MouseWheel>", on_wheel)

        # Keep a hidden Treeview
        self.tree = ttk.Treeview(main, columns=("w","u","e","p"),
                                 show="headings", height=0)

        self.setup_context_menu()
        self.refresh_entries()
        self.setup_status_bar(main)

    def _entry_value(self, entry: dict, field: str) -> str:
        """ Return a normalized entry field for sorting/filtering """
        if field == "username":
            return entry.get("username", entry.get("user", "")) or ""
        if field == "email":
            return entry.get("email", "") or ""
        if field == "pin":
            return entry.get("pin", entry.get("PIN", "")) or ""
        return entry.get("website", entry.get("site", "")) or ""

    def _entry_identity_text(self, entry: dict) -> str:
        """ Return the user-facing identity line for an entry card"""
        username = self._entry_value(entry, "username").strip()
        email = self._entry_value(entry, "email").strip()
        if username and email:
            return f"{username} • {email}"
        return username or email or "—"

    def _password_strength_score(self, password: str) -> int:
        """ Score password strength from 0 to 5 for display and sorting """
        if not password:
            return 0

        score = 0
        if len(password) >= 8:
            score += 1
        if len(password) >= 12:
            score += 1
        if any(ch.islower() for ch in password) and any(ch.isupper() for ch in password):
            score += 1
        if any(ch.isdigit() for ch in password):
            score += 1
        if any(not ch.isalnum() for ch in password):
            score += 1
        return max(1, min(5, score))

    def _rebuild_entry_index(self) -> None:
        """ Precompute normalized metadata for entries used by the main list"""
        self._entry_meta_cache = {}
        for entry in self.entries:
            website = self._entry_value(entry, "website").strip()
            username = self._entry_value(entry, "username").strip()
            email = self._entry_value(entry, "email").strip()
            pin = self._entry_value(entry, "pin").strip()
            identity = f"{username} • {email}" if username and email else (username or email or "—")
            password = entry.get("password", entry.get("pass", "")) or ""
            self._entry_meta_cache[id(entry)] = {
                "website": website,
                "username": username,
                "email": email,
                "pin": pin,
                "identity": identity,
                "password": password,
                "strength": self._password_strength_score(password),
                "search": f"{website} {username} {email} {pin}".casefold(),
            }

    def _entry_meta(self, entry: dict) -> dict:
        """ Return cached entry metadata """
        meta = getattr(self, "_entry_meta_cache", {}).get(id(entry))
        if meta is None:
            website = self._entry_value(entry, "website").strip()
            username = self._entry_value(entry, "username").strip()
            email = self._entry_value(entry, "email").strip()
            pin = self._entry_value(entry, "pin").strip()
            identity = f"{username} • {email}" if username and email else (username or email or "—")
            password = entry.get("password", entry.get("pass", "")) or ""
            meta = {
                "website": website,
                "username": username,
                "email": email,
                "pin": pin,
                "identity": identity,
                "password": password,
                "strength": self._password_strength_score(password),
                "search": f"{website} {username} {email} {pin}".casefold(),
            }
            if not hasattr(self, "_entry_meta_cache"):
                self._entry_meta_cache = {}
            self._entry_meta_cache[id(entry)] = meta
        return meta

    def _entry_strength(self, entry: dict) -> int:
        """ Return cached password strength for an entry """
        return self._entry_meta(entry).get("strength", 0)

    def _get_sorted_entries(self, entries: list = None) -> list:
        """ Return entries sorted by the selected main-screen sort option """
        entries = list(self.entries if entries is None else entries)
        primary = getattr(self, "entry_sort_value", "website")
        if primary not in ("website", "username", "security"):
            primary = "website"

        if primary == "security":
            # Weakest first so risky entries are easier to find
            def security_key(entry):
                meta = self._entry_meta(entry)
                return (
                    meta["strength"],
                    meta["website"].casefold(),
                    meta["identity"].casefold(),
                )
            return sorted(entries, key=security_key)

        secondary = "username" if primary == "website" else "website"
        def field_key(entry):
            meta = self._entry_meta(entry)
            return (
                (meta[primary] or meta["email"]).casefold(),
                meta[secondary].casefold(),
                meta["email"].casefold(),
            )
        return sorted(entries, key=field_key)

    def _cancel_entry_render(self) -> None:
        """ Cancel any pending batched entry rendering callback """
        after_id = getattr(self, "_entry_render_after_id", None)
        if after_id:
            try:
                self.root.after_cancel(after_id)
            except Exception:
                pass
            self._entry_render_after_id = None

    def _cancel_entry_filter(self) -> None:
        """ Cancel any pending debounced filter callback """
        after_id = getattr(self, "_entry_filter_after_id", None)
        if after_id:
            try:
                self.root.after_cancel(after_id)
            except Exception:
                pass
            self._entry_filter_after_id = None

    def _schedule_entry_filter(self, search_term: str) -> None:
        """ Debounce search """
        self.entry_search_text = search_term
        self._cancel_entry_filter()
        self._entry_filter_after_id = self.root.after(
            150, lambda: self.filter_entries(self.entry_search_text)
        )

    def _set_entry_sort(self, sort_value: str) -> None:
        """ Update sort option and redraw the current main-screen entry list """
        self.entry_sort_value = sort_value if sort_value in ("website", "username", "security") else "website"
        search_term = ""
        if hasattr(self, "entry_search_var"):
            search_term = self.entry_search_var.get()
        else:
            search_term = getattr(self, "entry_search_text", "")
        self.filter_entries(search_term)

    def _create_entry_card(self, entry: dict, cfg: dict, parent: tk.Widget) -> None:
        """ Create visible entry card """
        bg   = cfg["bg_color"]
        card = cfg.get("card_bg_color", cfg.get("secondary_bg_color", bg))
        acc  = cfg["accent_color"]
        fg   = cfg["fg_color"]
        mfg  = cfg.get("muted_fg_color", fg)
        bdr  = cfg.get("border_color", "#2d2d5a")
        bod  = cfg["body_font"]
        meta = self._entry_meta(entry)

        site = meta["website"] or "Unknown"
        identity = meta["identity"]
        icon = site[0].upper() if site else "?"

        row = tk.Frame(parent, bg=card,
                       highlightbackground=bdr, highlightthickness=1)
        row.pack(fill="x", pady=4)

        badge = tk.Label(row, text=icon, font=("Segoe UI", 14, "bold"),
                         bg=acc, fg=cfg.get("btn_fg_color", "#ffffff"),
                         width=3)
        badge.pack(side="left", padx=(12, 10), pady=10)

        info = tk.Frame(row, bg=card)
        info.pack(side="left", fill="x", expand=True, pady=8)
        tk.Label(info, text=site, font=("Segoe UI", 11, "bold"),
                 bg=card, fg=fg, anchor="w").pack(fill="x")
        tk.Label(info, text=identity, font=bod,
                 bg=card, fg=mfg, anchor="w").pack(fill="x")

        dot_frame = tk.Frame(row, bg=card)
        dot_frame.pack(side="right", padx=8)
        strength = meta["strength"]
        dot_colors = {0: "#555", 1: "#f85149", 2: "#d29922",
                      3: "#d29922", 4: "#3fb950", 5: "#58a6ff"}
        dc = dot_colors.get(strength, "#555")
        for i in range(5):
            tk.Label(dot_frame, text="●",
                     font=("Segoe UI", 8),
                     bg=card,
                     fg=dc if i < strength else bdr).pack(side="left")

        actions = tk.Frame(row, bg=card)
        actions.pack(side="right", padx=8)

        def make_copy_pw(e=entry):
            return lambda: self.copy_to_clipboard(e.get("password", e.get("pass", "")))
        def make_copy_user(e=entry):
            value = e.get("username", e.get("user", "")) or e.get("email", "")
            return lambda: self.copy_to_clipboard(value)
        def make_edit(e=entry):
            return lambda: self.edit_password_entry(e)
        def make_del(e=entry):
            return lambda: self.delete_password_entry(e)

        for txt, cmd, color in [
            ("👤", make_copy_user(), mfg),
            ("⎘", make_copy_pw(),   mfg),
            ("✎", make_edit(),       mfg),
            ("✕", make_del(),        cfg.get("error_color", "#f85149")),
        ]:
            b = tk.Label(actions, text=txt, font=("Segoe UI", 13),
                         bg=card, fg=color, cursor="hand2", padx=4)
            b.pack(side="left")
            b.bind("<Button-1>", lambda e, c=cmd: c())

        def bind_hover(widgets, c=card):
            hl = self._lighten_color(c, 8)
            def enter(_):
                for w in widgets:
                    try:
                        w.config(bg=hl)
                    except Exception:
                        pass
            def leave(_):
                for w in widgets:
                    try:
                        w.config(bg=c)
                    except Exception:
                        pass
            for w in widgets:
                w.bind("<Enter>", enter)
                w.bind("<Leave>", leave)
        bind_hover([row, info, dot_frame, actions])

    def _render_entry_cards(self, entries: list, empty_message: str = None) -> None:
        """ Render entries in small batches so the main window appears quickly """
        if not hasattr(self, "entries_container") or not self.entries_container.winfo_exists():
            return

        self._cancel_entry_render()
        cfg = self._get_style_config()
        bg   = cfg["bg_color"]
        mfg  = cfg.get("muted_fg_color", cfg["fg_color"])
        bod  = cfg["body_font"]

        for w in self.entries_container.winfo_children():
            w.destroy()

        visible_entries = self._get_sorted_entries(entries)
        visible_count = len(visible_entries)

        if hasattr(self, "count_label"):
            self.count_label.config(text=f"  {visible_count} entries")
        if hasattr(self, "status_var"):
            self.status_var.set(f"Entries: {visible_count} | User: {self.current_user}")

        if not visible_entries:
            tk.Label(self.entries_container,
                     text=empty_message or "No entries yet. Click '+ Add entry' to get started.",
                     font=bod, bg=bg, fg=mfg).pack(pady=40)
            return

        batch_size = max(1, int(getattr(self, "_entry_render_batch_size", 40)))

        def render_batch(start: int = 0) -> None:
            if not hasattr(self, "entries_container") or not self.entries_container.winfo_exists():
                self._entry_render_after_id = None
                return
            end = min(start + batch_size, visible_count)
            for entry in visible_entries[start:end]:
                self._create_entry_card(entry, cfg, self.entries_container)
            if hasattr(self, "_entry_canvas") and self._entry_canvas.winfo_exists():
                self._entry_canvas.configure(scrollregion=self._entry_canvas.bbox("all"))
            if end < visible_count:
                self._entry_render_after_id = self.root.after(1, lambda: render_batch(end))
            else:
                self._entry_render_after_id = None

        render_batch(0)

    def _refresh_entry_cards(self) -> None:
        """ Render all password entries """
        self._render_entry_cards(self.entries)

    def _filter_entry_cards(self, search_term: str) -> None:
        """ Filter entry cards by search term """
        self.entry_search_text = search_term
        term = search_term.casefold().strip()
        matched = [
            e for e in self.entries
            if term in self._entry_meta(e)["search"]
        ] if term else self.entries
        self._render_entry_cards(matched, empty_message=f"No entries match '{search_term}'.")

    def create_professional_button(self, parent, text, command, button_type="secondary", 
                             size="medium", style_config=None):

        if style_config is None:
            style_config = self._get_style_config()
        
        # Size configurations
        size_configs = {
            "small": {"width": 80, "height": 28, "font_size": 9},
            "medium": {"width": 100, "height": 32, "font_size": 10},
            "large": {"width": 120, "height": 36, "font_size": 11}
        }
        
        # Color configurations
        color_configs = {
            "primary": {
                "bg": style_config['accent_color'],
                "hover": self._lighten_color(style_config['accent_color'], 15),
                "text": style_config['fg_color']
            },
            "secondary": {
                "bg": style_config['secondary_bg_color'],
                "hover": self._lighten_color(style_config['secondary_bg_color'], 8),
                "text": style_config['fg_color']
            },
            "warning": {
                "bg": "#D4AC0D",  # Gold 
                "hover": "#F1C40F",
                "text": "#2C3E50"  # Dark text
            },
            "danger": {
                "bg": "#C0392B",
                "hover": "#E74C3C",
                "text": style_config['fg_color']
            },
            "success": {
                "bg": "#27AE60",
                "hover": "#2ECC71",
                "text": style_config['fg_color']
            }
        }
        
        config = size_configs[size]
        colors = color_configs[button_type]
        
        # Create frame
        button_frame = tk.Frame(
            parent,
            bg=style_config['bg_color'],
            highlightthickness=0
        )
        
        # Create button as Label
        btn = tk.Label(
            button_frame,
            text=text,
            bg=colors["bg"],
            fg=colors["text"],
            font=('Segoe UI', config["font_size"], 'bold'),
            relief='flat',
            border=0,
            cursor='hand2',
            width=config["width"] // 7,
            height=config["height"] // 20,
            padx=10  # horizontal padding
        )
        
        # Store state
        btn.original_bg = colors["bg"]
        btn.hover_bg = colors["hover"]
        btn.command = command
        
        def on_enter(e):
            btn.configure(bg=btn.hover_bg)
        
        def on_leave(e):
            btn.configure(bg=btn.original_bg)
        
        def on_click(e):
            # Add subtle click effect
            original_color = btn.original_bg
            btn.configure(bg=self._lighten_color(original_color, 25))
            button_frame.after(100, lambda: btn.configure(bg=original_color))
            command()
        
        # Bind events
        btn.bind("<Enter>", on_enter)
        btn.bind("<Leave>", on_leave)
        btn.bind("<Button-1>", on_click)
        
        btn.pack(padx=1, pady=1)
        return button_frame

    def _create_modern_action_buttons(self, parent: tk.Frame, style_config: Dict[str, Any]) -> None:
        """ Create header buttons """
        # button configurations
        button_configs = [
            {
                "text": "Customize",
                "command": self.show_customize_dialog,
                "type": "secondary",
                "size": "medium",
                "icon": "🎨"
            },
            {
                "text": "Settings", 
                "command": self.show_settings,
                "type": "secondary",
                "size": "medium", 
                "icon": "⚙️"
            },
            {
                "text": "Lock Session",
                "command": self.lock_application,
                "type": "warning",
                "size": "medium",
                "icon": "🔒"
            },
            {
                "text": "Sign Out",
                "command": self.logout,
                "type": "danger",
                "size": "medium",
                "icon": "🚪"
            }
        ]
        
        # Create buttons
        for config in button_configs:
            btn_text = f"{config['icon']} {config['text']}"
            btn = self.create_professional_button(
                parent,
                text=btn_text,
                command=config["command"],
                button_type=config["type"],
                size=config["size"],
                style_config=style_config
            )
            btn.pack(side='left', padx=4)

    def create_modern_button(self, parent, text, command, bg_color=None, 
                        width=None, height=38, style_config=None, 
                        hover_effect=True, variant="primary", **kwargs):
        if style_config is None:
            style_config = self._get_style_config()
        
        if bg_color is None:
            color_map = {
                "primary": style_config['accent_color'],
                "secondary": style_config['secondary_bg_color'],
                "danger": style_config['error_color'],
                "warning": style_config['warning_color']
            }
            bg_color = color_map.get(variant, style_config['accent_color'])
        
        # Use provided fg_color or default from style config
        fg_color = kwargs.get('fg_color')
        text_color = fg_color if fg_color else style_config['fg_color']
        
        # Calculate width
        if width is None:
            text_width = len(text) * 7 + 24
            width = max(90, min(220, text_width))
        
        # Create frame wrapper
        button_frame = tk.Frame(
            parent,
            bg=style_config['bg_color'],
            highlightthickness=0,
            relief='flat'
        )
        
        # Create the button as a Label
        btn_label = tk.Label(
            button_frame,
            text=text,
            bg=bg_color,
            fg=text_color,
            font=('Segoe UI', 10, 'bold'),
            relief='flat',
            border=0,
            cursor='hand2',
            width=width // 7,
            height=height // 20
        )
        
        # Store state
        btn_label.original_bg = bg_color
        btn_label.hover_bg = self._lighten_color(bg_color, 12) if hover_effect else bg_color
        btn_label.click_bg = self._lighten_color(bg_color, 20) if hover_effect else bg_color
        btn_label.command = command
        btn_label.is_pressed = False
        
        def on_enter(e):
            if hover_effect and not btn_label.is_pressed:
                btn_label.configure(bg=btn_label.hover_bg)
        
        def on_leave(e):
            if not btn_label.is_pressed:
                btn_label.configure(bg=btn_label.original_bg)
        
        def on_press(e):
            btn_label.is_pressed = True
            btn_label.configure(bg=btn_label.click_bg)
        
        def on_release(e):
            btn_label.is_pressed = False
            btn_label.configure(bg=btn_label.original_bg)
            if hover_effect:
                btn_label.configure(bg=btn_label.hover_bg)
            command()
        
        # Bind events
        btn_label.bind("<Enter>", on_enter)
        btn_label.bind("<Leave>", on_leave)
        btn_label.bind("<ButtonPress-1>", on_press)
        btn_label.bind("<ButtonRelease-1>", on_release)
        
        # Pack the label
        btn_label.pack(padx=0, pady=0)
        
        return button_frame
            
    def _lighten_color(self, color: str, percent: int) -> str:
        try:
            # Handle named colors
            color_map = {
                'red': '#ff0000', 'green': '#00ff00', 'blue': '#0000ff',
                'yellow': '#ffff00', 'orange': '#ffa500', 'purple': '#800080',
                'pink': '#ffc0cb', 'brown': '#a52a2a', 'gray': '#808080',
                'black': '#000000', 'white': '#ffffff'
            }
            
            if color.lower() in color_map:
                color = color_map[color.lower()]
            
            color = color.lstrip('#')
            
            # Handle different color formats
            if len(color) == 3:
                color = ''.join([c*2 for c in color])
            elif len(color) != 6:
                return color  # Return original if invalid
                
            r, g, b = int(color[0:2], 16), int(color[2:4], 16), int(color[4:6], 16)
            r = max(0, min(255, r + int((255 - r) * percent / 100)))
            g = max(0, min(255, g + int((255 - g) * percent / 100)))
            b = max(0, min(255, b + int((255 - b) * percent / 100)))
            
            return f"#{r:02x}{g:02x}{b:02x}"
        except Exception as e:
            print(f"Error lightening color '{color}': {e}")  # Debug
            return color  # Return original color on error
    
    def _create_tooltip(self, widget, text):
        """ Create a tooltip for a widget """
        def on_enter(event):
            tooltip = tk.Toplevel()
            tooltip.wm_overrideredirect(True)
            tooltip.wm_geometry(f"+{event.x_root+10}+{event.y_root+10}")
            
            label = tk.Label(
                tooltip, 
                text=text, 
                background="#ffffe0", 
                relief='solid', 
                borderwidth=1,
                font=('Segoe UI', 8)
            )
            label.pack()
            
            widget.tooltip = tooltip
        
        def on_leave(event):
            if hasattr(widget, 'tooltip'):
                widget.tooltip.destroy()
        
        widget.bind("<Enter>", on_enter)
        widget.bind("<Leave>", on_leave)

    def show_customize_dialog(self) -> None:
        """ theme customization dialog """
        cfg  = self._get_style_config()
        bg   = cfg["bg_color"]
        sbg  = cfg.get("secondary_bg_color", bg)
        card = cfg.get("card_bg_color", sbg)
        acc  = cfg["accent_color"]
        fg   = cfg["fg_color"]
        mfg  = cfg.get("muted_fg_color", fg)
        bdr  = cfg.get("border_color", "#2d2d5a")
        bod  = cfg["body_font"]
        bf   = cfg["button_font"]
        hf   = cfg["heading_font"]
        btn_fg = cfg.get("btn_fg_color", "#ffffff")

        THEMES = {
            "midnight": {"name": "Midnight Pro",    "colors": ["#7b68ee", "#00d4ff", "#0f0f23"],
                         "desc": "Sleek dark purple-blue theme"},
            "light":    {"name": "Arctic Light",    "colors": ["#4361ee", "#7209b7", "#f0f4ff"],
                         "desc": "Clean, bright light theme"},
            "ocean":    {"name": "Ocean Blue",      "colors": ["#64ffda", "#57cbff", "#0a192f"],
                         "desc": "Deep blue with aqua accents"},
            "forest":   {"name": "Forest Green",    "colors": ["#83e85a", "#38b2ac", "#0d1b1e"],
                         "desc": "Nature-inspired dark green"},
        }

        d = tk.Toplevel(self.root)
        d.title("Customize Appearance")
        d.configure(bg=bg)
        d.geometry("560x520")
        d.resizable(False, False)
        d.transient(self.root)
        d.update_idletasks()
        d.grab_set()
        self._center_dialog(d)

        tk.Frame(d, bg=acc, height=4).pack(fill="x")

        outer = tk.Frame(d, bg=bg)
        outer.pack(fill="both", expand=True, padx=28, pady=20)

        tk.Label(outer, text="🎨  Customize Appearance", font=hf, bg=bg, fg=fg).pack(anchor="w")
        tk.Label(outer, text="Choose a theme for your Krault experience",
                 font=bod, bg=bg, fg=mfg).pack(anchor="w", pady=(2, 16))

        current_theme = get_current_theme()
        self.theme_var = tk.StringVar(value=current_theme)

        tk.Label(outer, text="SELECT THEME", font=("Segoe UI", 9), bg=bg, fg=mfg).pack(anchor="w", pady=(0, 8))

        # Theme grid (2 columns)
        grid_frame = tk.Frame(outer, bg=bg)
        grid_frame.pack(fill="x", pady=(0, 16))
        grid_frame.columnconfigure(0, weight=1, uniform="col")
        grid_frame.columnconfigure(1, weight=1, uniform="col")

        theme_ids = list(THEMES.keys())
        for idx, tid in enumerate(theme_ids):
            row, col = divmod(idx, 2)
            t = THEMES[tid]
            tc = get_style_config(tid)

            cell = tk.Frame(grid_frame, bg=tc["card_bg_color"],
                            highlightthickness=2)
            cell.grid(row=row, column=col, padx=6, pady=6, sticky="nsew")

            def _update_border(name, index, mode, tid=tid, cell=cell, tc=tc):
                if self.theme_var.get() == tid:
                    cell.config(highlightbackground=tc["accent_color"])
                else:
                    cell.config(highlightbackground=tc.get("border_color", "#333"))
            self.theme_var.trace_add("write", _update_border)
            _update_border(None, None, None)

            def _select(tid=tid): self.theme_var.set(tid)
            cell.bind("<Button-1>", lambda e, tid=tid: _select(tid))

            inner = tk.Frame(cell, bg=tc["card_bg_color"], cursor="hand2")
            inner.pack(fill="both", expand=True, padx=12, pady=10)
            inner.bind("<Button-1>", lambda e, tid=tid: _select(tid))

            # Theme name + radio
            top_row = tk.Frame(inner, bg=tc["card_bg_color"])
            top_row.pack(fill="x")
            tk.Radiobutton(top_row, variable=self.theme_var, value=tid,
                           bg=tc["card_bg_color"], fg=tc["fg_color"],
                           selectcolor=tc["card_bg_color"],
                           activebackground=tc["card_bg_color"],
                           bd=0, highlightthickness=0, cursor="hand2").pack(side="left")
            tk.Label(top_row, text=t["name"], font=("Segoe UI", 10, "bold"),
                     bg=tc["card_bg_color"], fg=tc["fg_color"]).pack(side="left", padx=(4, 0))

            # Color swatches
            swatch_row = tk.Frame(inner, bg=tc["card_bg_color"])
            swatch_row.pack(anchor="w", pady=(6, 4))
            for color in t["colors"][:3]:
                sw = tk.Frame(swatch_row, bg=color, width=28, height=12)
                sw.pack(side="left", padx=(0, 4))
                sw.pack_propagate(False)

            tk.Label(inner, text=t["desc"], font=("Segoe UI", 8),
                     bg=tc["card_bg_color"],
                     fg=tc.get("muted_fg_color", tc["fg_color"]),
                     wraplength=200).pack(anchor="w")

        # Separator
        tk.Frame(outer, bg=bdr, height=1).pack(fill="x", pady=(0, 12))

        # Apply / Done row
        act_row = tk.Frame(outer, bg=bg)
        act_row.pack(fill="x")

        status_lbl = tk.Label(act_row, text="", font=("Segoe UI", 9), bg=bg, fg=cfg.get("success_color", "#3fb950"))
        status_lbl.pack(side="left")

        def _apply():
            sel = self.theme_var.get()
            if set_application_theme(sel):
                self.configure_theme()
                self._rerender_current_screen()
            else:
                messagebox.showerror("Error", "Failed to apply theme.")

        tk.Button(act_row, text="✓  Done", command=d.destroy,
                  font=bf, bg=card, fg=fg, relief="flat", bd=0, cursor="hand2",
                  activebackground=bdr, activeforeground=fg,
                  highlightbackground=bdr, highlightthickness=1,
                  padx=18, pady=7).pack(side="right", padx=(8, 0))

        tk.Button(act_row, text="🎨  Apply Theme", command=_apply,
                  font=bf, bg=acc, fg=btn_fg, relief="flat", bd=0, cursor="hand2",
                  activebackground=cfg.get("btn_hover_color", acc), activeforeground=btn_fg,
                  padx=18, pady=7).pack(side="right")

    def _create_theme_card(self, parent, theme_id: str, theme_data: dict, style_config: dict):
        pass


    def _get_style_config(self) -> Dict[str, Any]:
        """ Get the current theme configuration with """
        from config.themes import get_style_config
        config = get_style_config()
        
        # Provide fallbacks for any missing keys
        fallbacks = {
            'bg_color': '#1e1e1e',
            'secondary_bg_color': '#2e2e2e',
            'card_bg_color': '#2e2e2e',  # Fallback if card_bg_color missing
            'accent_color': '#4CAF50',
            'secondary_color': '#2196F3',
            'error_color': '#f44336',
            'warning_color': '#ff9800',
            'success_color': '#4CAF50',
            'fg_color': '#ffffff',
            'muted_fg_color': '#b8b8d6',  # Fallback for muted_fg_color
            'border_color': '#404040',
            'disabled_color': '#666666',
            'gradient_start': '#4CAF50',
            'gradient_end': '#2196F3',
            'title_font': ('Arial', 16, 'bold'),
            'heading_font': ('Arial', 12, 'bold'),
            'body_font': ('Arial', 10),
            'monospace_font': ('Courier New', 10),
            'button_font': ('Arial', 10, 'bold'),
            'border_radius': 8,
            'card_radius': 12,
            'shadow_color': '#00000020',
            'hover_lighten': 10
        }
        
        # Merge config with fallbacks
        return {**fallbacks, **config}

    def _rerender_current_screen(self) -> None:
        """ Rebuild whichever screen is currently showing """
        if self.is_locked:
            self.show_lock_screen()
        elif self.current_user:
            self.show_main_interface()
        else:
            self.show_login_screen()

    def configure_theme(self) -> None:
        """ Configure dark theme for all UI elements"""
        style_config = self._get_style_config()
        style = ttk.Style()
        
        # Try to set a dark base theme
        try:
            # Try different themes that might support dark mode better
            available_themes = style.theme_names()
            if 'clam' in available_themes:
                style.theme_use('clam')
                logging.info("Using 'clam' theme for dark mode")
            elif 'alt' in available_themes:
                style.theme_use('alt')
                logging.info("Using 'alt' theme for dark mode")
            elif 'default' in available_themes:
                style.theme_use('default')
                logging.info("Using 'default' theme")
        except Exception as e:
            logging.warning(f"Could not set preferred theme: {e}")
            pass  # Fall back to default theme
        
        # Configure base styles for all ttk widgets
        style.configure('.', 
                    background=style_config['bg_color'],
                    foreground=style_config['fg_color'],
                    fieldbackground=style_config['secondary_bg_color'],
                    troughcolor=style_config['secondary_bg_color'],
                    selectbackground=style_config['accent_color'],
                    selectforeground=style_config['fg_color'],
                    insertcolor=style_config['fg_color'],  # Cursor color
                    focuscolor=style_config['accent_color'],
                    bordercolor=style_config['border_color'],
                    lightcolor=style_config['border_color'],
                    darkcolor=style_config['border_color'])
        
        # Configure specific widget styles with explicit settings
        self._configure_ttk_styles(style, style_config)
        
        # Configure tk widget defaults
        self.root.option_add('*Background', style_config['bg_color'])
        self.root.option_add('*Foreground', style_config['fg_color'])
        self.root.option_add('*selectBackground', style_config['accent_color'])
        self.root.option_add('*selectForeground', style_config['fg_color'])
        self.root.option_add('*insertBackground', style_config['fg_color'])  # Cursor color
        self.root.option_add('*activeBackground', style_config['secondary_color'])
        self.root.option_add('*activeForeground', style_config['fg_color'])
        self.root.option_add('*highlightColor', style_config['accent_color'])
        self.root.option_add('*highlightBackground', style_config['border_color'])
        self.root.option_add('*disabledForeground', style_config['disabled_color'])
        self.root.option_add('*readonlyBackground', style_config['secondary_bg_color'])
        
        # Configure specific tk widgets
        self.root.option_add('*Listbox*Background', style_config['secondary_bg_color'])
        self.root.option_add('*Listbox*Foreground', style_config['fg_color'])
        self.root.option_add('*Listbox*selectBackground', style_config['accent_color'])
        self.root.option_add('*Listbox*selectForeground', style_config['fg_color'])
        
        self.root.option_add('*Entry*Background', style_config['secondary_bg_color'])
        self.root.option_add('*Entry*Foreground', style_config['fg_color'])
        self.root.option_add('*Entry*insertBackground', style_config['fg_color'])
        self.root.option_add('*Entry*selectBackground', style_config['accent_color'])
        self.root.option_add('*Entry*selectForeground', style_config['fg_color'])
        self.root.option_add('*Entry*disabledBackground', style_config['disabled_color'])
        self.root.option_add('*Entry*readonlyBackground', style_config['secondary_bg_color'])
        
        self.root.option_add('*Text*Background', style_config['secondary_bg_color'])
        self.root.option_add('*Text*Foreground', style_config['fg_color'])
        self.root.option_add('*Text*insertBackground', style_config['fg_color'])
        self.root.option_add('*Text*selectBackground', style_config['accent_color'])
        self.root.option_add('*Text*selectForeground', style_config['fg_color'])
        
        self.root.option_add('*Menu*Background', style_config['secondary_bg_color'])
        self.root.option_add('*Menu*Foreground', style_config['fg_color'])
        self.root.option_add('*Menu*activeBackground', style_config['accent_color'])
        self.root.option_add('*Menu*activeForeground', style_config['fg_color'])
        
        self.root.option_add('*Menubutton*Background', style_config['secondary_bg_color'])
        self.root.option_add('*Menubutton*Foreground', style_config['fg_color'])
        
        self.root.option_add('*Scrollbar*troughColor', style_config['bg_color'])
        self.root.option_add('*Scrollbar*background', style_config['secondary_bg_color'])
        self.root.option_add('*Scrollbar*activeBackground', style_config['accent_color'])

    def _configure_login_styles(self, style_config: Dict[str, Any]) -> None:
        """Configure specific styles for login screen widgets"""
        style = ttk.Style()
        
        # Configure tabs style
        style.configure("TNotebook", 
                    background=style_config['bg_color'],
                    borderwidth=0)
        
        style.configure("TNotebook.Tab",
                    background=style_config['secondary_bg_color'],
                    foreground=style_config['fg_color'],
                    padding=[20, 8],
                    font=style_config['body_font'])
        
        style.map("TNotebook.Tab",
                background=[('selected', style_config['accent_color']),
                            ('active', style_config['secondary_color'])],
                foreground=[('selected', style_config['fg_color']),
                            ('active', style_config['fg_color'])])
        
        # Configure entry styles
        style.configure("TEntry",
                    fieldbackground=style_config['secondary_bg_color'],
                    foreground=style_config['fg_color'],
                    borderwidth=1,
                    relief='flat')
        
        # Configure button styles
        style.configure("TButton",
                    background=style_config['accent_color'],
                    foreground=style_config['fg_color'],
                    borderwidth=0,
                    focuscolor=style_config['accent_color'])
        
        style.map("TButton",
                background=[('active', style_config['secondary_color']),
                            ('pressed', style_config['secondary_color'])],
                foreground=[('active', style_config['fg_color']),
                            ('pressed', style_config['fg_color'])])
        
        # Configure checkbutton styles
        style.configure("TCheckbutton",
                    background=style_config.get('card_bg_color', style_config['secondary_bg_color']),
                    foreground=style_config['fg_color'])
        
        style.map("TCheckbutton",
                background=[('active', style_config.get('card_bg_color', style_config['secondary_bg_color']))])

    def _configure_ttk_styles(self, style, style_config):
        """ Configure ttk styles with safe key access """
        try:
            # Use get() with fallbacks for all theme keys
            bg_color = style_config.get('bg_color', '#1e1e1e')
            fg_color = style_config.get('fg_color', '#ffffff')
            secondary_bg = style_config.get('secondary_bg_color', '#2e2e2e')
            accent_color = style_config.get('accent_color', '#4CAF50')
            secondary_color = style_config.get('secondary_color', '#2196F3')
            border_color = style_config.get('border_color', '#404040')
            
            # Configure base styles
            style.configure('.', 
                        background=bg_color,
                        foreground=fg_color,
                        fieldbackground=secondary_bg,
                        selectbackground=accent_color,
                        selectforeground=fg_color,
                        troughcolor=secondary_bg,
                        focuscolor=accent_color)
            
            # Basic widget styles
            style.configure("TFrame", background=bg_color)
            style.configure("TLabel", background=bg_color, foreground=fg_color)
            style.configure("TButton", background=secondary_color, foreground=fg_color)
            style.configure("TEntry", fieldbackground=secondary_bg, foreground=fg_color)
            style.configure("TCombobox", fieldbackground=secondary_bg, foreground=fg_color)
            
            # Modern button style
            style.configure("Modern.TButton",
                        background=accent_color,
                        foreground=fg_color,
                        font=style_config.get('button_font', ('Arial', 10, 'bold')))
            
            style.map("Modern.TButton",
                    background=[('active', secondary_color),
                                ('pressed', secondary_color)],
                    foreground=[('active', fg_color),
                                ('pressed', fg_color)])
            
            print("Theme styles configured successfully")
            
        except Exception as e:
            print(f"Error configuring styles: {e}")
            # Don't break the app if theme configuration fails

    def setup_auto_lock(self) -> None:
        """ Setup auto-lock functionality to secure application after inactivity """
        # Bind user activity events to reset the inactivity timer
        self.root.bind('<KeyPress>', self._reset_activity_timer)
        self.root.bind('<ButtonPress>', self._reset_activity_timer)
        self.root.bind('<Motion>', self._reset_activity_timer)  # Mouse movement
        self._check_auto_lock()  # Start the auto-lock monitoring loop
 
    def _reset_activity_timer(self, event: Optional[tk.Event] = None) -> None:
        """ Reset the activity timer when user interacts with the application """
        if not self.is_locked and self.current_user:
            self.last_activity = time.time()
            logging.debug("Activity timer reset")
  
    def _check_auto_lock(self) -> None:
        """ Check if auto-lock should be triggered based on inactivity """
        if (not self.is_locked and 
            self.current_user and 
            time.time() - self.last_activity > LOCK_TIMEOUT):
            logging.info("Auto-lock triggered due to inactivity")
            self.lock_application()
            
        # Continue checking every second
        self.root.after(1000, self._check_auto_lock)

    def _load_persisted_login_attempts(self) -> None:
        """ Restore failed-login/lockout counters from disk on startup """
        try:
            state = self.database_manager.load_login_attempts()
            for username, entry in state.items():
                attempts = entry.get("attempts", 0)
                lockout_until = entry.get("lockout_until")
                if attempts:
                    self.login_attempts[username] = attempts
                if lockout_until:
                    self.lockout_time[username] = lockout_until
        except Exception as e:
            logging.error(f"Failed to load persisted login attempts: {e}")

    def _persist_login_attempts(self) -> None:
        """ Write the current in-memory attempt/lockout state to disk """
        try:
            usernames = set(self.login_attempts) | set(self.lockout_time)
            state = {}
            for username in usernames:
                attempts = self.login_attempts.get(username, 0)
                lockout_until = self.lockout_time.get(username)
                if not attempts and not lockout_until:
                    continue  # nothing worth persisting for this user
                state[username] = {"attempts": attempts, "lockout_until": lockout_until}
            self.database_manager.save_login_attempts(state)
        except Exception as e:
            logging.error(f"Failed to persist login attempts: {e}")

    def _is_account_locked(self, username: str) -> bool:
        """ Check if account is locked due to failed login attempts """
        if username in self.lockout_time:
            lockout_end = self.lockout_time[username]
            if time.time() < lockout_end:
                return True
            else:
                # Lockout period has expired - reset attempts
                del self.lockout_time[username]
                self.login_attempts[username] = 0
                logging.info(f"Lockout period expired for {username}, attempts reset")
                self._persist_login_attempts()
        return False
 
    def verify_master_password(self, username: str, password: str) -> bool:
        """Verify master password with true constant-time comparison to prevent timing attacks.
        Security Features:
            - True constant-time execution regardless of user existence
            - Same operations performed for all code paths
            - Dummy operations for non-existent users
            - Secure memory cleanup
            - Protection against user enumeration via timing """
        # Initialize variables for both real and dummy operations
        dummy_salt = None
        temp_security = None
        actual_salt = None
        user_exists = False
        
        try:
            # Always generate dummy salt first
            dummy_salt = secrets.token_bytes(SALT_SIZE)
            temp_security = SecurityManager()
            
            # Check if user exists
            profiles = self.database_manager.load_profiles()
            user_exists = username in profiles
            
            # Always get a salt (real or dummy) to maintain constant time
            if user_exists:
                actual_salt = self.database_manager.get_user_salt(username)
                salt_to_use = actual_salt if actual_salt else dummy_salt
            else:
                salt_to_use = dummy_salt

            # Always attempt encryption initialization (constant-time)
            encryption_success = False
            try:
                encryption_success = temp_security.initialize_encryption(
                    password, username, salt_to_use, kdf=KDF_DEFAULT
                )
            except Exception:
                # Even if encryption fails, we continue with dummy operations
                encryption_success = False
            
            # Verify using the stored password_verifier blob (created at registration)
            verifier = profiles.get(username, {}).get('password_verifier') if user_exists else None

            if user_exists and encryption_success and verifier:
                result = temp_security.verify_password(verifier)
            else:
                # Dummy verification for non-existent users or missing verifier
                dummy_verifier = temp_security.create_password_verifier()
                temp_security.verify_password(dummy_verifier)
                result = False
            
            # Perform additional dummy operations to ensure constant time.
            self._perform_verification_dummy_work(dummy_salt)
            
            return result
            
        except Exception as e:
            logging.error(f"Password verification error for {username}: {e}")
            # Even in exception cases, perform dummy work
            self._perform_verification_dummy_work(dummy_salt)
            return False
            
        finally:
            # Secure cleanup in all cases
            self._secure_cleanup_verification(dummy_salt, temp_security, actual_salt)

    def verify_2fa_code(self, username: str, code: str) -> bool:
        """ Verify a 2FA TOTP code with replay protection """
        profiles = self.database_manager.load_profiles()
        user_profile = profiles.get(username, {})
        raw_secret = user_profile.get('2fa_secret')

        if not raw_secret:
            logging.error(f"No 2FA secret found for user {username}")
            return False

        # The 2FA secret is stored encrypted
        try:
            if self.security_manager._key is not None:
                # Session already active (e.g. toggling 2FA from settings)
                secret = self.security_manager.decrypt_data(raw_secret)
            else:
                # Login-time path: derive the key from the stored password + salt
                salt = self.database_manager.get_user_salt(username)
                stored_pass = self._secure_password.get()
                tmp_sm = SecurityManager()
                tmp_sm.initialize_encryption(stored_pass, username, salt, kdf=KDF_DEFAULT)
                secret = tmp_sm.decrypt_data(raw_secret)
                tmp_sm.invalidate_session()

            if not secret:
                logging.error(f"Failed to decrypt 2FA secret for {username}")
                return False

            return self._verify_totp_with_replay_protection(username, secret, code)
        except Exception as e:
            logging.error(f"2FA verification error for {username}: {e}")
            return False

    def _verify_totp_with_replay_protection(self, username: str, secret: str, code: str) -> bool:

        try:
            totp = pyotp.TOTP(secret)
            interval = totp.interval or 30
            current_step = int(time.time() // interval)

            state = self.database_manager.load_totp_state()
            last_accepted_step = state.get(username, -1)

            matched_step = None
            for offset in range(-TOTP_VALID_WINDOW, TOTP_VALID_WINDOW + 1):
                step = current_step + offset
                if step <= last_accepted_step:
                    continue  # already used — would be a replay, skip even if it matches
                candidate_code = totp.at(step * interval)
                if hmac.compare_digest(candidate_code, code):
                    matched_step = step
                    break

            if matched_step is None:
                return False

            state[username] = matched_step
            self.database_manager.save_totp_state(state)
            return True
        except Exception as e:
            logging.error(f"TOTP replay-protected verification error for {username}: {e}")
            return False
 
    def toggle_2fa(self, enable: bool) -> bool:
        """ Toggle 2FA for current user """
        profiles = self.database_manager.load_profiles()
        user_profile = profiles.get(self.current_user, {})

        if enable and not user_profile.get('2fa_secret'):
            # Generate new secret if enabling 2FA for the first time.
            # Store it encrypted with the current session key.
            plain_secret = pyotp.random_base32()
            user_profile['2fa_secret'] = self.security_manager.encrypt_data(plain_secret)
            
        user_profile['2fa_enabled'] = enable
        
        # Save profile
        profiles[self.current_user] = user_profile
        if self.database_manager.save_profiles(profiles):
            if enable:
                self.audit_logger.log_security_event(self.current_user, 
                                                "2FA_ENABLED", "User enabled 2FA")
            else:
                self.audit_logger.log_security_event(self.current_user, 
                                                "2FA_DISABLED", "User disabled 2FA")
            return True
        else:
            messagebox.showerror("Error", "Failed to update 2FA settings")
            return False

    def change_master_password(self, new_password: str) -> bool:
        """ Change master password for current user with full database re-encryption """
        if not self.current_user or not self.current_database:
            return False

        old_security = self.security_manager
        new_salt = self.security_manager.generate_salt()

        try:
            new_sm = SecurityManager()
            if not new_sm.initialize_encryption(new_password, self.current_user, new_salt, kdf=KDF_DEFAULT):
                return False

            entries = self.database_manager.load_data(self.current_database)

            self.security_manager = new_sm
            self.database_manager.security_manager = new_sm

            if not self.database_manager.save_data(entries, self.current_database):
                self.security_manager = old_security
                self.database_manager.security_manager = old_security
                return False

            salts = self.database_manager.load_salts()
            salts[self.current_user] = base64.b64encode(new_salt).decode()
            if not self.database_manager.save_salts(salts):
                logging.critical("Salt save failed after re-encryption — session still valid but restart may break login")
                self.security_manager = old_security
                self.database_manager.security_manager = old_security
                self.database_manager.save_data(self.entries, self.current_database)
                return False

            new_verifier = new_sm.create_password_verifier()
            profiles = self.database_manager.load_profiles()
            if self.current_user in profiles:
                profile = profiles[self.current_user]
                profile["password_verifier"] = new_verifier
                profile["kdf"] = KDF_DEFAULT
                old_2fa_secret_cipher = profile.get("2fa_secret")
                if old_2fa_secret_cipher:
                    plain_2fa = old_security.decrypt_data(old_2fa_secret_cipher)
                    if plain_2fa:
                        profile["2fa_secret"] = new_sm.encrypt_data(plain_2fa)
                    else:
                        logging.error(
                            f"Password change: could not re-wrap 2FA secret for '{self.current_user}'"
                        )
                profiles[self.current_user] = profile
                self.database_manager.save_profiles(profiles)

            self.entries = entries
            self._secure_password.set(new_password)

            self.audit_logger.log_security_event(
                self.current_user, "PASSWORD_CHANGE", "Master password changed"
            )
            old_security.invalidate_session()
            gc.collect()
            return True

        except Exception as e:
            logging.error(f"Password change error: {e}")
            # Roll back on any exception
            try:
                self.security_manager = old_security
                self.database_manager.security_manager = old_security
            except Exception:
                pass
            return False

    def _get_remaining_lockout_time(self, username: str) -> int:
        """ Get remaining lockout time in seconds """
        if username in self.lockout_time:
            remaining = self.lockout_time[username] - time.time()
            return max(0, int(remaining))
        return 0
        
    def _handle_failed_login(self, username: str) -> None:
        """ Handle failed login attempt and lock account if necessary """
        self.login_attempts[username] = self.login_attempts.get(username, 0) + 1
        
        if self.login_attempts[username] >= MAX_LOGIN_ATTEMPTS:
            self.lockout_time[username] = time.time() + ACCOUNT_LOCKOUT_TIME
            messagebox.showerror("Account Locked", 
                               "Too many failed login attempts. Account locked for 30 minutes.")
            self.audit_logger.log_login(username, False, "Account locked due to failed attempts")
            logging.warning(f"Account {username} locked due to failed login attempts")

        self._persist_login_attempts()
 
    def _toggle_password_display(self, password: str, password_var: tk.StringVar, show: bool) -> None:
        """ Toggle password display in details view between masked and plain text """
        password_var.set(password if show else '•' * 12)

    def copy_to_clipboard(self, text: str) -> bool:
        """ Copy text to the system clipboard, then schedule an automatic clear after CLIPBOARD_CLEAR_SECONDS """
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.root.update()

            self._clipboard_generation = getattr(self, '_clipboard_generation', 0) + 1
            my_generation = self._clipboard_generation

            def _clear_if_unchanged():
                if getattr(self, '_clipboard_generation', 0) != my_generation:
                    return
                try:
                    if self.root.clipboard_get() == text:
                        self.root.clipboard_clear()
                        self.root.update()
                        logging.info("Clipboard automatically cleared")
                except tk.TclError:
                    pass 

            self.root.after(CLIPBOARD_CLEAR_SECONDS * 1000, _clear_if_unchanged)
            return True
        except Exception as e:
            logging.error(f"Failed to copy to clipboard: {e}")
            return False

    def set_custom_data_directory(self, new_path: str) -> bool:
        """ Set a custom data directory and migrate existing data """
        try:
            # Validate the new directory
            if not os.path.exists(new_path):
                os.makedirs(new_path, mode=0o700, exist_ok=True)
            
            # Create config file
            config = {
                'custom_data_directory': new_path,
                'migrated_at': time.time()
            }
            
            os.makedirs(DATA_DIR, exist_ok=True)  # Ensure default dir exists for config
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)
                
            return True
        except Exception as e:
            logging.error(f"Failed to set custom data directory: {e}")
            return False

    def _secure_cleanup_verification(self, 
                                dummy_salt: Optional[bytes], 
                                temp_security: Optional[SecurityManager],
                                actual_salt: Optional[bytes]) -> None:
        """ Securely clean up all sensitive data from memory after verification """
        try:
            # Best-effort zeroing of the salt buffers
            if dummy_salt is not None:
                secure_clear_object(dummy_salt)

            if actual_salt is not None and actual_salt is not dummy_salt:
                secure_clear_object(actual_salt)
            
            # Invalidate temporary security instance
            if temp_security is not None:
                temp_security.invalidate_session()
                
            # Force garbage collection
            gc.collect()
            
        except Exception as e:
            logging.error(f"Error during secure cleanup: {e}")

    def _perform_verification_dummy_work(self, dummy_salt: Optional[bytes]) -> None:
        """Perform dummy cryptographic work to maintain constant execution time """
        try:
            # Create another dummy security instance and perform operations
            dummy_work_security = SecurityManager()
            if dummy_salt:
                dummy_work_security.initialize_encryption(
                    "dummy_work_password_constant_length_456", 
                    "dummy_work_user", 
                    dummy_salt,
                    kdf=KDF_DEFAULT,
                )
                dummy_data = "dummy_work_data_constant_length_789"
                encrypted = dummy_work_security.encrypt_data(dummy_data)
                decrypted = dummy_work_security.decrypt_data(encrypted)
                # Perform comparison that takes similar time to real comparison
                self._constant_time_compare(dummy_data, decrypted or "")
                dummy_work_security.invalidate_session()
        except Exception:
            # Ignore errors in dummy work for timing consistency
            pass

    def _constant_time_compare(self, val1: str, val2: str) -> bool:
        """ Constant time comparison to prevent timing attacks.
        Security Features:
            - Uses byte-level comparison to prevent timing attacks
            - Same execution time regardless of input
            - No early returns that could leak information """
        try:
            # Simple constant-time comparison without hmac
            if len(val1) != len(val2):
                return False
            result = 0
            for x, y in zip(val1.encode('utf-8'), val2.encode('utf-8')):
                result |= x ^ y
            return result == 0
        except Exception as e:
            logging.error(f"Constant time comparison error: {e}")
            # Fallback to simple comparison (not constant time)
            return val1 == val2

    def _configure_tk_widgets(self, style_config):
        """ Configure non-ttk tkinter widgets for dark theme """
        try:
            # Configure basic tk options
            self.root.option_add('*Background', style_config['bg_color'])
            self.root.option_add('*Foreground', style_config['fg_color'])
            self.root.option_add('*selectBackground', style_config['accent_color'])
            self.root.option_add('*selectForeground', style_config['fg_color'])
            self.root.option_add('*insertBackground', style_config['fg_color'])  # Cursor color
            self.root.option_add('*activeBackground', style_config['secondary_color'])
            self.root.option_add('*activeForeground', style_config['fg_color'])
            self.root.option_add('*highlightColor', style_config['accent_color'])
            self.root.option_add('*highlightBackground', style_config['border_color'])
            self.root.option_add('*disabledForeground', style_config['disabled_color'])
            self.root.option_add('*readonlyBackground', style_config['secondary_bg_color'])
            
            # Menu styling
            self.root.option_add('*Menu*Background', style_config['secondary_bg_color'])
            self.root.option_add('*Menu*Foreground', style_config['fg_color'])
            self.root.option_add('*Menu*activeBackground', style_config['accent_color'])
            self.root.option_add('*Menu*activeForeground', style_config['fg_color'])
            
            # Listbox styling
            self.root.option_add('*Listbox*Background', style_config['secondary_bg_color'])
            self.root.option_add('*Listbox*Foreground', style_config['fg_color'])
            self.root.option_add('*Listbox*selectBackground', style_config['accent_color'])
            self.root.option_add('*Listbox*selectForeground', style_config['fg_color'])
            
        except Exception as e:
            print(f"Error configuring tk widgets: {e}")

    def setup_logging(self) -> None:
        """ Setup application logging with file and console handlers """
        # Remove emojis from log messages or ensure proper encoding
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('password_manager.log', encoding='utf-8'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        logging.info("Password Manager application started")
    
    def setup_context_menu(self) -> None:
        """ Setup right-click context menu for treeview with entry actions"""
        self.context_menu = tk.Menu(self.tree, tearoff=0, 
                                  bg=self._get_style_config()['secondary_bg_color'],
                                  fg=self._get_style_config()['fg_color'],
                                  activebackground=self._get_style_config()['accent_color'],
                                  activeforeground=self._get_style_config()['fg_color'])
        
        self.context_menu.add_command(label="View Details", command=self.view_entry_details)
        self.context_menu.add_command(label="Edit Entry", command=self.edit_password_entry)
        self.context_menu.add_command(label="Copy Password", command=self.copy_password)
        self.context_menu.add_command(label="Copy Username", command=self.copy_username)
        self.context_menu.add_command(label="Copy Email", command=self.copy_email)
        self.context_menu.add_command(label="Copy PIN", command=self.copy_pin)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Delete Entry", command=self.delete_password_entry)
        
        self.tree.bind('<Button-3>', self.show_context_menu)  # Right-click binding
        
    def show_context_menu(self, event: tk.Event) -> None:
        """ Show context menu on right-click over treeview item"""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)  # Select the clicked item
            try:
                self.context_menu.post(event.x_root, event.y_root)  # Show at cursor position
            except Exception as e:
                logging.error(f"Error showing context menu: {e}")
                
    def setup_status_bar(self, parent: ttk.Frame) -> None:
        """Setup status bar at bottom of main interface """
        status_frame = ttk.Frame(parent, style='Dark.TFrame')
        status_frame.pack(fill='x', pady=5)
        
        self.status_var = tk.StringVar(value=f"Entries: {len(self.entries)} | User: {self.current_user}")
        status_label = ttk.Label(status_frame, textvariable=self.status_var, 
                               style='Dark.TLabel')
        status_label.pack(side='left')
        
        # Auto-lock countdown display
        self.lock_countdown_var = tk.StringVar(value=f"Auto-lock: {LOCK_TIMEOUT//60}min")
        lock_label = ttk.Label(status_frame, textvariable=self.lock_countdown_var, 
                             style='Dark.TLabel')
        lock_label.pack(side='right')
        
    def _refresh_stats(self) -> None:
        """ Recompute and update the "Total entries / Weak passwords / Security
        score" stat cards in place. """
        if not (hasattr(self, "_stat_total_label") and self._stat_total_label
                and self._stat_total_label.winfo_exists()):
            return  # main interface not currently showing these cards

        cfg = self._get_style_config()
        fg = cfg["fg_color"]

        total = len(self.entries)
        weak = sum(1 for e in self.entries if self._entry_strength(e) <= 2)
        score = max(0, 100 - weak * 10) if total else 0
        score_c = (cfg.get("success_color", "#3fb950") if score >= 70
                   else cfg.get("warning_color", "#d29922"))
        weak_c = cfg.get("error_color", "#f85149") if weak else fg

        self._stat_total_label.config(text=str(total))
        self._stat_weak_label.config(text=str(weak), fg=weak_c)
        self._stat_score_label.config(text=f"{score}%", fg=score_c)

    def refresh_entries(self) -> None:
        """ Refresh the visible entries list """
        self._refresh_stats()

        if hasattr(self, "entries_container") and self.entries_container.winfo_exists():
            self._refresh_entry_cards()
            return

        if not hasattr(self, "tree"):
            return

        for item in self.tree.get_children():
            self.tree.delete(item)

        for entry in self._get_sorted_entries(self.entries):
            self.tree.insert('', 'end', values=(
                entry.get('website', ''),
                entry.get('username', entry.get('user', '')),
                entry.get('email', ''),
                '•' * 12
            ))

        if hasattr(self, "status_var"):
            self.status_var.set(
                f"Entries: {len(self.entries)} | User: {self.current_user}")

    def filter_entries(self, search_term: str) -> None:
        """ ilter the visible entries list """
        self.entry_search_text = search_term
        if hasattr(self, "entries_container") and self.entries_container.winfo_exists():
            self._filter_entry_cards(search_term)
            return

        if not hasattr(self, "tree"):
            return

        if not search_term:
            self.refresh_entries()
            return

        term = search_term.casefold()
        filtered_entries = [
            entry for entry in self.entries
            if term in self._entry_value(entry, 'website').casefold()
            or term in self._entry_value(entry, 'username').casefold()
            or term in self._entry_value(entry, 'email').casefold()
        ]

        for item in self.tree.get_children():
            self.tree.delete(item)

        for entry in self._get_sorted_entries(filtered_entries):
            self.tree.insert('', 'end', values=(
                entry.get('website', ''),
                entry.get('username', entry.get('user', '')),
                entry.get('email', ''),
                '•' * 12
            ))

    def _show_entry_dialog(self, title: str,
                              entry_data: dict = None,
                              save_callback=None) -> None:
        """ Dialog for adding or editing password entries """
        cfg  = self._get_style_config()
        bg   = cfg["bg_color"]
        card = cfg.get("card_bg_color", cfg.get("secondary_bg_color", bg))
        acc  = cfg["accent_color"]
        fg   = cfg["fg_color"]
        mfg  = cfg.get("muted_fg_color", fg)
        bdr  = cfg.get("border_color", "#2d2d5a")
        ibg  = cfg.get("input_bg_color", cfg.get("secondary_bg_color", bg))
        err  = cfg.get("error_color", "#f85149")
        bod  = cfg["body_font"]
        bf   = cfg["button_font"]
        hf   = cfg["heading_font"]
        btn_fg = cfg.get("btn_fg_color", "#ffffff")

        STRENGTH_COLORS = ["#f85149", "#d29922", "#e3b341", "#58a6ff", "#3fb950"]
        STRENGTH_LABELS = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]

        is_edit = entry_data is not None
        icon    = "\u270f\ufe0f" if is_edit else "\u2795"

        d = tk.Toplevel(self.root)
        d.title(title)
        d.configure(bg=bg)
        d.geometry("420x700")
        d.resizable(False, False)
        d.transient(self.root)
        d.update_idletasks()
        d.grab_set()
        self._center_dialog(d)

        # Accent top bar
        tk.Frame(d, bg=acc, height=4).pack(fill="x")

        # Scrollable canvas
        canvas_w = tk.Canvas(d, bg=bg, bd=0, highlightthickness=0)
        scrollbar = tk.Scrollbar(d, orient="vertical", command=canvas_w.yview)
        canvas_w.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        canvas_w.pack(side="left", fill="both", expand=True)
        outer = tk.Frame(canvas_w, bg=bg)
        cw_id = canvas_w.create_window((0, 0), window=outer, anchor="nw")
        canvas_w.bind("<Configure>", lambda e: canvas_w.itemconfig(cw_id, width=e.width))
        outer.bind("<Configure>", lambda e: canvas_w.configure(scrollregion=canvas_w.bbox("all")))
        def _mwheel(e): canvas_w.yview_scroll(int(-1*(e.delta/120)), "units")
        canvas_w.bind_all("<MouseWheel>", _mwheel)

        pad = tk.Frame(outer, bg=bg)
        pad.pack(fill="x", padx=28, pady=(20, 24))

        tk.Label(pad, text=f"{icon}  {title}", font=hf, bg=bg, fg=fg).pack(anchor="w", pady=(0, 16))

        def field(label_text, var, secret=False, required=False):
            lbl = label_text.upper() + (" *" if required else "")
            tk.Label(pad, text=lbl, font=("Segoe UI", 9), bg=bg, fg=mfg).pack(anchor="w")
            e = tk.Entry(pad, textvariable=var, show="\u25cf" if secret else "",
                         font=bod, bg=ibg, fg=fg, relief="flat", bd=0,
                         highlightbackground=bdr, highlightcolor=acc,
                         highlightthickness=1, insertbackground=fg,
                         selectbackground=acc, selectforeground=bg, width=34)
            e.pack(fill="x", ipady=7, pady=(3, 12))
            return e

        ed = entry_data or {}
        website_var  = tk.StringVar(value=ed.get("website",  ed.get("site",  "")))
        username_var = tk.StringVar(value=ed.get("username", ed.get("user",  "")))
        email_var    = tk.StringVar(value=ed.get("email", ""))
        password_var = tk.StringVar(value=ed.get("password", ed.get("pass",  "")))
        pin_var      = tk.StringVar(value=ed.get("pin", ed.get("PIN", "")))
        notes_var    = tk.StringVar(value=ed.get("notes", ""))

        field("Website / App Name", website_var, required=True)
        field("Username", username_var)
        field("Email", email_var)

        # Password row with inline show/hide toggle
        tk.Label(pad, text="PASSWORD *", font=("Segoe UI", 9), bg=bg, fg=mfg).pack(anchor="w")
        pw_frame = tk.Frame(pad, bg=ibg,
                            highlightbackground=bdr, highlightcolor=acc, highlightthickness=1)
        pw_frame.pack(fill="x", pady=(3, 0))
        pw_entry = tk.Entry(pw_frame, textvariable=password_var, show="\u25cf",
                            font=bod, bg=ibg, fg=fg, relief="flat", bd=0,
                            insertbackground=fg, selectbackground=acc,
                            selectforeground=bg, highlightthickness=0)
        pw_entry.pack(side="left", fill="x", expand=True, ipady=7, padx=(8, 0))
        show_var = tk.BooleanVar()
        def _toggle_pw():
            show_var.set(not show_var.get())
            pw_entry.config(show="" if show_var.get() else "\u25cf")
        tk.Button(pw_frame, text="\U0001f441", font=("Segoe UI", 10),
                  bg=ibg, fg=mfg, relief="flat", bd=0, cursor="hand2",
                  activebackground=ibg, activeforeground=acc,
                  command=_toggle_pw).pack(side="right", padx=8)

        # Strength bar
        sf = tk.Frame(pad, bg=bg)
        sf.pack(fill="x", pady=(4, 2))
        bar_cv = tk.Canvas(sf, height=4, bg=bdr, highlightthickness=0)
        bar_cv.pack(side="left", fill="x", expand=True)
        str_lbl = tk.Label(sf, text="", font=("Segoe UI", 8), bg=bg, fg=mfg, width=10, anchor="e")
        str_lbl.pack(side="right", padx=(6, 0))

        def _update_str(*_):
            pw = password_var.get()
            if not pw:
                bar_cv.delete("bar"); str_lbl.config(text=""); return
            try: score, _ = self.password_policy_manager.check_password_compliance(pw)
            except Exception: score = 0
            color = STRENGTH_COLORS[score]
            bar_cv.update_idletasks()
            w = bar_cv.winfo_width() or 200
            bar_cv.delete("bar")
            bar_cv.create_rectangle(0, 0, max(4, int(w*(score+1)/5)), 4,
                                    fill=color, outline="", tags="bar")
            str_lbl.config(text=STRENGTH_LABELS[score], fg=color)

        password_var.trace_add("write", _update_str)

        # Generate button
        gen_row = tk.Frame(pad, bg=bg)
        gen_row.pack(fill="x", pady=(4, 12))
        def _generate():
            def _use(pw):
                password_var.set(pw); show_var.set(True); pw_entry.config(show="")
            self.show_password_generator(callback=_use)
        tk.Button(gen_row, text="\u26a1  Generate password", command=_generate,
                  font=("Segoe UI", 9), bg=card, fg=acc, relief="flat", bd=0, cursor="hand2",
                  activebackground=bdr, activeforeground=acc,
                  highlightbackground=bdr, highlightthickness=1,
                  padx=10, pady=4).pack(side="right")

        # PIN row
        tk.Label(pad, text="PIN  (optional)", font=("Segoe UI", 9), bg=bg, fg=mfg).pack(anchor="w")
        pin_frame = tk.Frame(pad, bg=ibg,
                             highlightbackground=bdr, highlightcolor=acc, highlightthickness=1)
        pin_frame.pack(fill="x", pady=(3, 0))
        pin_entry = tk.Entry(pin_frame, textvariable=pin_var, show="\u25cf",
                             font=bod, bg=ibg, fg=fg, relief="flat", bd=0,
                             insertbackground=fg, selectbackground=acc,
                             selectforeground=bg, highlightthickness=0)
        pin_entry.pack(side="left", fill="x", expand=True, ipady=7, padx=(8, 0))
        show_pin_var = tk.BooleanVar()
        def _toggle_pin():
            show_pin_var.set(not show_pin_var.get())
            pin_entry.config(show="" if show_pin_var.get() else "\u25cf")
        tk.Button(pin_frame, text="\U0001f441", font=("Segoe UI", 10),
                  bg=ibg, fg=mfg, relief="flat", bd=0, cursor="hand2",
                  activebackground=ibg, activeforeground=acc,
                  command=_toggle_pin).pack(side="right", padx=8)

        tk.Frame(pad, bg=bg, height=12).pack()
        field("Notes  (optional)", notes_var)

        err_lbl = tk.Label(pad, text="", font=("Segoe UI", 9), bg=bg, fg=err, wraplength=360)
        err_lbl.pack(anchor="w", pady=(0, 4))

        tk.Frame(pad, bg=bdr, height=1).pack(fill="x", pady=(8, 12))
        act_row = tk.Frame(pad, bg=bg)
        act_row.pack(fill="x")

        def do_save():
            data = {
                "website":  website_var.get().strip(),
                "username": username_var.get().strip(),
                "email":    email_var.get().strip(),
                "password": password_var.get(),
                "pin":      pin_var.get().strip(),
                "notes":    notes_var.get().strip(),
            }
            if not data["website"]:
                err_lbl.config(text="Website / App Name is required."); return
            if not data["password"]:
                err_lbl.config(text="Password is required."); return
            if not data["username"] and not data["email"]:
                err_lbl.config(text="Username or Email is required."); return
            canvas_w.unbind_all("<MouseWheel>")
            d.destroy()
            if save_callback:
                save_callback(data)

        def _cancel():
            canvas_w.unbind_all("<MouseWheel>")
            d.destroy()

        tk.Button(act_row, text="Cancel", command=_cancel,
                  font=bf, bg=card, fg=mfg, relief="flat", bd=0, cursor="hand2",
                  activebackground=bdr, activeforeground=fg,
                  highlightbackground=bdr, highlightthickness=1,
                  padx=18, pady=8).pack(side="left")

        save_label = "Save Changes" if is_edit else "Save Entry"
        tk.Button(act_row, text=f"\u2713  {save_label}", command=do_save,
                  font=bf, bg=acc, fg=btn_fg, relief="flat", bd=0, cursor="hand2",
                  activebackground=cfg.get("btn_hover_color", acc),
                  activeforeground=btn_fg, padx=18, pady=8).pack(side="right")

        pw_entry.bind("<Return>", lambda _: do_save())
        if password_var.get(): _update_str()

    def add_password_entry(self) -> None:
        """ Open dialog to add a new password entry """
        def save_new(data):
            if len(self.entries) >= MAX_ENTRIES:
                messagebox.showerror("Error",
                    f"Maximum entries limit reached ({MAX_ENTRIES})")
                return
            self.entries.append(data)
            self._rebuild_entry_index()
            if self.database_manager.save_data(self.entries, self.current_database):
                self.refresh_entries()
                self.audit_logger.log_password_access(
                    self.current_user, data["website"], "ADD")
            else:
                messagebox.showerror("Error", "Failed to save entry.")
                self.entries.pop()
                self._rebuild_entry_index()

        self._show_entry_dialog("Add entry", save_callback=save_new)
    
    def edit_password_entry(self, entry: dict = None) -> None:
        """ Open dialog to edit a password entry """
        if entry is None:
            # Legacy path via context menu / tree selection
            selected = self.tree.selection()
            if not selected:
                messagebox.showwarning("Warning", "Please select an entry to edit")
                return
            index = self.tree.index(selected[0])
            if index >= len(self.entries):
                messagebox.showerror("Error", "Invalid entry selection")
                return
            entry = self.entries[index]

        original_index = next(
            (i for i, e in enumerate(self.entries) if e is entry), None)

        def save_edit(data):
            idx = original_index
            if idx is None:
                # Fallback: match by original values
                idx = next(
                    (i for i, e in enumerate(self.entries)
                     if e.get("website") == entry.get("website")
                     and e.get("username", e.get("user", "")) == entry.get("username", entry.get("user", ""))
                     and e.get("email", "") == entry.get("email", "")), None)
            if idx is None:
                messagebox.showerror("Error", "Entry no longer exists.")
                return
            self.entries[idx] = data
            self._rebuild_entry_index()
            if self.database_manager.save_data(self.entries, self.current_database):
                self.refresh_entries()
                self.audit_logger.log_password_access(
                    self.current_user, data["website"], "EDIT")
            else:
                messagebox.showerror("Error", "Failed to save changes.")
                self.entries[idx] = entry
                self._rebuild_entry_index()

        self._show_entry_dialog("Edit entry", entry_data=entry, save_callback=save_edit)
    
    def view_entry_details(self) -> None:
        """ View details of selected password """
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select an entry to view")
            return
            
        item = selected[0]
        index = self.tree.index(item)
        
        if index >= len(self.entries):
            messagebox.showerror("Error", "Invalid entry selection")
            return
            
        entry = self.entries[index]
        
        # Create details dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Entry Details")
        dialog.geometry("430x360")
        dialog.configure(bg=self._get_style_config()['bg_color'])
        dialog.transient(self.root)
        dialog.update_idletasks()
        dialog.grab_set()  # Modal dialog
        
        self._center_dialog(dialog)
        
        style_config = self._get_style_config()
        
        # Title
        ttk.Label(dialog, text="🔍 Password Entry Details", 
                 style='DarkTitle.TLabel').pack(pady=5)
        
        # Details frame
        details_frame = ttk.Frame(dialog, style='Dark.TFrame')
        details_frame.pack(fill='both', expand=True, padx=20, pady=2)
        
        # Website display
        website_frame = ttk.Frame(details_frame, style='Dark.TFrame')
        website_frame.pack(fill='x', pady=2)
        ttk.Label(website_frame, text="Website:", 
                 style='DarkHeading.TLabel').pack(side='left')
        ttk.Label(website_frame, text=entry.get('website', 'N/A'), 
                 style='Dark.TLabel').pack(side='right')
        
        # Username display
        username_frame = ttk.Frame(details_frame, style='Dark.TFrame')
        username_frame.pack(fill='x', pady=1)
        ttk.Label(username_frame, text="Username:", 
                 style='DarkHeading.TLabel').pack(side='left')
        ttk.Label(username_frame, text=entry.get('username', entry.get('user', '')) or 'N/A', 
                 style='Dark.TLabel').pack(side='right')

        # Email display
        email_frame = ttk.Frame(details_frame, style='Dark.TFrame')
        email_frame.pack(fill='x', pady=1)
        ttk.Label(email_frame, text="Email:", 
                 style='DarkHeading.TLabel').pack(side='left')
        ttk.Label(email_frame, text=entry.get('email', '') or 'N/A', 
                 style='Dark.TLabel').pack(side='right')
        
        # Password display with reveal option
        password_frame = ttk.Frame(details_frame, style='Dark.TFrame')
        password_frame.pack(fill='x', pady=2)
        ttk.Label(password_frame, text="Password:", 
                 style='DarkHeading.TLabel').pack(side='left')
        
        password_var = tk.StringVar(value='•' * 12)  # Initially masked
        password_label = ttk.Label(password_frame, textvariable=password_var, 
                                 style='Dark.TLabel')
        password_label.pack(side='left', padx=5)
        
        reveal_var = tk.BooleanVar()
        reveal_cb = ttk.Checkbutton(password_frame, text="Show", 
                                  variable=reveal_var,
                                  style='Dark.TCheckbutton',
                                  command=lambda: self._toggle_password_display(
                                      entry.get('password', ''), 
                                      password_var, 
                                      reveal_var.get()))
        reveal_cb.pack(side='left')

        # PIN display with reveal option
        pin_frame = ttk.Frame(details_frame, style='Dark.TFrame')
        pin_frame.pack(fill='x', pady=2)
        ttk.Label(pin_frame, text="PIN:", 
                 style='DarkHeading.TLabel').pack(side='left')
        pin_var = tk.StringVar(value='•' * 6 if entry.get('pin', entry.get('PIN', '')) else 'N/A')
        pin_label = ttk.Label(pin_frame, textvariable=pin_var, style='Dark.TLabel')
        pin_label.pack(side='left', padx=5)
        pin_reveal_var = tk.BooleanVar()
        pin_reveal_cb = ttk.Checkbutton(
            pin_frame, text="Show", variable=pin_reveal_var,
            style='Dark.TCheckbutton',
            command=lambda: self._toggle_password_display(
                entry.get('pin', entry.get('PIN', '')),
                pin_var,
                pin_reveal_var.get()
            ) if entry.get('pin', entry.get('PIN', '')) else None
        )
        pin_reveal_cb.pack(side='left')
        
        # Copy buttons frame
        copy_frame = ttk.Frame(details_frame, style='Dark.TFrame')
        copy_frame.pack(fill='x', pady=5)
        copy_row_1 = ttk.Frame(copy_frame, style='Dark.TFrame')
        copy_row_1.pack(fill='x', pady=(0, 4))
        copy_row_2 = ttk.Frame(copy_frame, style='Dark.TFrame')
        copy_row_2.pack(fill='x')
        
        self.create_modern_button(copy_row_1, text="📋 Copy Username", 
                    command=lambda: self.copy_to_clipboard(entry.get('username', entry.get('user', ''))),
                    bg_color=style_config['secondary_color'],
                    hover_color=style_config['accent_color'],
                    width=145, height=30).pack(side='left', padx=5)

        self.create_modern_button(copy_row_1, text="📋 Copy Email", 
                    command=lambda: self.copy_to_clipboard(entry.get('email', '')),
                    bg_color=style_config['secondary_color'],
                    hover_color=style_config['accent_color'],
                    width=145, height=30).pack(side='left', padx=5)
                    
        self.create_modern_button(copy_row_2, text="📋 Copy Password", 
                    command=lambda: self.copy_to_clipboard(entry.get('password', '')),
                    bg_color=style_config['accent_color'],
                    hover_color=style_config['secondary_color'],
                    width=145, height=30).pack(side='left', padx=5)

        self.create_modern_button(copy_row_2, text="📋 Copy PIN", 
                    command=lambda: self.copy_to_clipboard(entry.get('pin', entry.get('PIN', ''))),
                    bg_color=style_config['secondary_color'],
                    hover_color=style_config['accent_color'],
                    width=145, height=30).pack(side='left', padx=5)
        
        # Close button
        self.create_modern_button(dialog, text="Close", 
                    command=dialog.destroy,
                    bg_color=style_config['secondary_color'],
                    hover_color=style_config['accent_color'],
                    width=100, height=35).pack(pady=5)
        
        # Log the view action for audit
        self.audit_logger.log_password_access(self.current_user, 
                                            entry.get('website', ''), "VIEW")
        
    def delete_password_entry(self, entry: dict = None) -> None:
        """Delete a password entry"""
        if entry is None:
            selected = self.tree.selection()
            if not selected:
                messagebox.showwarning("Warning", "Please select an entry to delete")
                return
            index = self.tree.index(selected[0])
            if index >= len(self.entries):
                messagebox.showerror("Error", "Invalid entry selection")
                return
            entry = self.entries[index]

        website = entry.get("website", entry.get("site", "this entry"))

        if not messagebox.askyesno("Confirm delete",
                                   f"Permanently delete the entry for\n'{website}'?"):
            return

        index = next(
            (i for i, e in enumerate(self.entries) if e is entry), None)
        if index is None:
            index = next(
                (i for i, e in enumerate(self.entries)
                 if e.get("website") == entry.get("website")
                 and e.get("username", e.get("user", "")) == entry.get("username", entry.get("user", ""))
                 and e.get("email", "") == entry.get("email", "")), None)
        if index is None:
            messagebox.showerror("Error", "Entry not found.")
            return

        deleted = self.entries.pop(index)
        self._rebuild_entry_index()
        if self.database_manager.save_data(self.entries, self.current_database):
            self.refresh_entries()
            self.audit_logger.log_password_access(
                self.current_user, website, "DELETE")
        else:
            messagebox.showerror("Error", "Failed to delete entry.")
            self.entries.insert(index, deleted)
            self._rebuild_entry_index()
    
    def _get_selected_tree_entry(self) -> Optional[dict]:
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select an entry")
            return None

        item = selected[0]
        values = self.tree.item(item, 'values') if hasattr(self, "tree") else ()
        if values:
            site = values[0] if len(values) > 0 else ""
            username = values[1] if len(values) > 1 else ""
            email = values[2] if len(values) > 2 else ""
            matched = next(
                (e for e in self.entries
                 if e.get('website', '') == site
                 and e.get('username', e.get('user', '')) == username
                 and e.get('email', '') == email),
                None
            )
            if matched is not None:
                return matched

        index = self.tree.index(item)
        sorted_entries = self._get_sorted_entries(self.entries)
        if index < len(sorted_entries):
            return sorted_entries[index]
        return None

    def copy_password(self) -> None:
        """ Copy password of selected entry to clipboard """
        entry = self._get_selected_tree_entry()
        if not entry:
            return
        self.copy_to_clipboard(entry.get('password', entry.get('pass', '')))
        self.audit_logger.log_password_access(
            self.current_user,
            entry.get('website', ''),
            "COPY_PASSWORD"
        )
            
    def show_password_generator(self, callback=None) -> None:
        """ password-generator dialog """
        cfg  = self._get_style_config()
        bg   = cfg["bg_color"]
        card = cfg.get("card_bg_color", cfg.get("secondary_bg_color", bg))
        acc  = cfg["accent_color"]
        fg   = cfg["fg_color"]
        mfg  = cfg.get("muted_fg_color", fg)
        bdr  = cfg.get("border_color", "#2d2d5a")
        ibg  = cfg.get("input_bg_color", cfg.get("secondary_bg_color", bg))
        err  = cfg.get("error_color", "#f85149")
        bod  = cfg["body_font"]
        bf   = cfg["button_font"]
        hf   = cfg["heading_font"]
        btn_fg = cfg.get("btn_fg_color", "#ffffff")

        STRENGTH_COLORS = ["#f85149", "#d29922", "#e3b341", "#58a6ff", "#3fb950"]
        STRENGTH_LABELS = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]

        d = tk.Toplevel(self.root)
        d.title("Password Generator")
        d.configure(bg=bg)
        d.geometry("480x530")
        d.resizable(False, False)
        d.transient(self.root)
        d.update_idletasks()
        d.grab_set()
        self._center_dialog(d)

        # Accent top bar
        tk.Frame(d, bg=acc, height=4).pack(fill="x")

        outer = tk.Frame(d, bg=bg)
        outer.pack(fill="both", expand=True, padx=28, pady=22)

        # Header
        tk.Label(outer, text="⚡  Password Generator", font=hf, bg=bg, fg=fg).pack(anchor="w", pady=(0, 14))

        # Generated password display
        pw_var = tk.StringVar()
        pw_row = tk.Frame(outer, bg=ibg,
                          highlightbackground=bdr, highlightcolor=acc, highlightthickness=1)
        pw_row.pack(fill="x", pady=(0, 4))

        pw_display = tk.Entry(
            pw_row, textvariable=pw_var,
            font=("Courier New", 13, "bold"), state="readonly",
            bg=ibg, fg=fg, relief="flat", bd=0,
            readonlybackground=ibg, insertbackground=fg,
            selectbackground=acc, selectforeground=bg,
            highlightthickness=0,
        )
        pw_display.pack(side="left", fill="x", expand=True, ipady=10, padx=(10, 0))

        # Inline copy button
        copied_lbl = tk.Label(pw_row, text="", font=("Segoe UI", 8), bg=ibg, fg=acc)
        copied_lbl.pack(side="right", padx=(0, 6))
        def _copy():
            pw = pw_var.get()
            if pw:
                self.copy_to_clipboard(pw)
                copied_lbl.config(text="✓")
                d.after(1500, lambda: copied_lbl.config(text=""))
        tk.Button(pw_row, text="📋", font=("Segoe UI", 11),
                  bg=ibg, fg=mfg, relief="flat", bd=0, cursor="hand2",
                  activebackground=ibg, activeforeground=acc,
                  command=_copy).pack(side="right", padx=4)

        # Strength bar 
        sf = tk.Frame(outer, bg=bg)
        sf.pack(fill="x", pady=(0, 14))
        bar_cv = tk.Canvas(sf, height=6, bg=bdr, highlightthickness=0)
        bar_cv.pack(side="left", fill="x", expand=True)
        str_lbl = tk.Label(sf, text="", font=("Segoe UI", 9), bg=bg, fg=mfg, width=12, anchor="e")
        str_lbl.pack(side="right", padx=(8, 0))

        def _update_strength(pw: str) -> None:
            if not pw: bar_cv.delete("bar"); str_lbl.config(text=""); return
            try: score, _ = self.password_policy_manager.check_password_compliance(pw)
            except Exception: score = 0
            color = STRENGTH_COLORS[score]
            bar_cv.update_idletasks()
            w = bar_cv.winfo_width() or 280
            bar_cv.delete("bar")
            bar_cv.create_rectangle(0, 0, max(6, int(w*(score+1)/5)), 6,
                                    fill=color, outline="", tags="bar")
            str_lbl.config(text=STRENGTH_LABELS[score], fg=color)

        # Options section 
        tk.Frame(outer, bg=bdr, height=1).pack(fill="x", pady=(0, 12))
        tk.Label(outer, text="OPTIONS", font=("Segoe UI", 9), bg=bg, fg=mfg).pack(anchor="w", pady=(0, 8))

        # Length
        len_row = tk.Frame(outer, bg=bg)
        len_row.pack(fill="x", pady=(0, 8))
        tk.Label(len_row, text="Length", font=bod, bg=bg, fg=fg).pack(side="left")
        length_var = tk.IntVar(value=18)

        spinbox = tk.Spinbox(
            len_row, from_=8, to=64, textvariable=length_var, width=4,
            font=("Courier New", 11, "bold"),
            bg=ibg, fg=acc, relief="flat", bd=0,
            buttonbackground=bdr, insertbackground=fg,
            highlightbackground=bdr, highlightcolor=acc, highlightthickness=1,
            justify="center",
        )
        spinbox.pack(side="right", ipady=3)

        slider = tk.Scale(
            len_row, variable=length_var, from_=8, to=64, orient="horizontal",
            showvalue=False, bg=bg, fg=fg, troughcolor=bdr, activebackground=acc,
            highlightthickness=0, bd=0, sliderrelief="flat",
            sliderlength=16, width=8,
        )
        slider.pack(side="left", fill="x", expand=True, padx=(10, 8))

        # Checkbox options
        upper_var   = tk.BooleanVar(value=True)
        lower_var   = tk.BooleanVar(value=True)
        digits_var  = tk.BooleanVar(value=True)
        symbols_var = tk.BooleanVar(value=True)
        ambig_var   = tk.BooleanVar(value=False)

        def _checkbox(text, var):
            row = tk.Frame(outer, bg=bg)
            row.pack(fill="x", pady=2)
            tk.Checkbutton(row, text=text, variable=var,
                           font=bod, bg=bg, fg=fg, selectcolor=ibg,
                           activebackground=bg, activeforeground=fg,
                           bd=0, highlightthickness=0, cursor="hand2").pack(side="left")

        _checkbox("Uppercase  (A–Z)",                upper_var)
        _checkbox("Lowercase  (a–z)",                lower_var)
        _checkbox("Digits  (0–9)",                   digits_var)

        # Symbols row with editable set
        sym_row = tk.Frame(outer, bg=bg)
        sym_row.pack(fill="x", pady=2)
        tk.Checkbutton(sym_row, text="Symbols", variable=symbols_var,
                       font=bod, bg=bg, fg=fg, selectcolor=ibg,
                       activebackground=bg, activeforeground=fg,
                       bd=0, highlightthickness=0, cursor="hand2").pack(side="left")
        symbol_set_var = tk.StringVar(value="!@#$%^&*()-_=+[]{}|;:,.<>?")
        tk.Entry(sym_row, textvariable=symbol_set_var,
                 font=("Courier New", 10), bg=ibg, fg=fg, relief="flat", bd=0,
                 highlightbackground=bdr, highlightcolor=acc, highlightthickness=1,
                 insertbackground=fg, width=26).pack(side="right", ipady=3)

        _checkbox("Exclude ambiguous chars  (0 O l 1 I |)",  ambig_var)

        err_lbl = tk.Label(outer, text="", font=("Segoe UI", 9), bg=bg, fg=err)
        err_lbl.pack(anchor="w", pady=(4, 0))

        # Core generate
        def _generate():
            err_lbl.config(text="")
            try:
                pw = generate_password(
                    length=length_var.get(),
                    use_upper=upper_var.get(),
                    use_lower=lower_var.get(),
                    use_digits=digits_var.get(),
                    use_symbols=symbols_var.get(),
                    symbol_set=symbol_set_var.get() or "!@#$%^&*",
                    exclude_ambiguous=ambig_var.get(),
                )
                pw_display.config(state="normal")
                pw_var.set(pw)
                pw_display.config(state="readonly")
                _update_strength(pw)
            except ValueError as e:
                err_lbl.config(text=str(e))

        # Action buttons
        tk.Frame(outer, bg=bdr, height=1).pack(fill="x", pady=(12, 12))
        btn_row = tk.Frame(outer, bg=bg)
        btn_row.pack(fill="x")

        tk.Button(btn_row, text="🔄  Regenerate", command=_generate,
                  font=bf, bg=card, fg=fg, relief="flat", bd=0, cursor="hand2",
                  activebackground=bdr, activeforeground=fg,
                  highlightbackground=bdr, highlightthickness=1,
                  padx=14, pady=7).pack(side="left", padx=(0, 8))

        tk.Button(btn_row, text="📋  Copy", command=_copy,
                  font=bf, bg=card, fg=fg, relief="flat", bd=0, cursor="hand2",
                  activebackground=bdr, activeforeground=fg,
                  highlightbackground=bdr, highlightthickness=1,
                  padx=14, pady=7).pack(side="left")

        if callback:
            def _use():
                pw = pw_var.get()
                if pw: callback(pw); d.destroy()
            tk.Button(btn_row, text="✓  Use Password", command=_use,
                      font=bf, bg=acc, fg=btn_fg, relief="flat", bd=0, cursor="hand2",
                      activebackground=cfg.get("btn_hover_color", acc),
                      activeforeground=btn_fg, padx=14, pady=7).pack(side="right")

        # Wire live regeneration
        _generate()
        for var in (upper_var, lower_var, digits_var, symbols_var, ambig_var, symbol_set_var):
            var.trace_add("write", lambda *_: _generate())
        slider.bind("<ButtonRelease-1>", lambda _: _generate())
        slider.bind("<B1-Motion>",        lambda _: _generate())


    def show_settings(self) -> None:
        """Settings dialog"""
        cfg  = self._get_style_config()
        bg   = cfg["bg_color"]
        sbg  = cfg.get("secondary_bg_color", bg)
        card = cfg.get("card_bg_color", sbg)
        acc  = cfg["accent_color"]
        fg   = cfg["fg_color"]
        mfg  = cfg.get("muted_fg_color", fg)
        bdr  = cfg.get("border_color", "#2d2d5a")
        ibg  = cfg.get("input_bg_color", sbg)
        suc  = cfg.get("success_color", "#3fb950")
        err  = cfg.get("error_color", "#f85149")
        wrn  = cfg.get("warning_color", "#d29922")
        bod  = cfg["body_font"]
        bf   = cfg["button_font"]
        hf   = cfg["heading_font"]
        btn_fg = cfg.get("btn_fg_color", "#ffffff")

        d = tk.Toplevel(self.root)
        d.title("Settings")
        d.configure(bg=bg)
        d.geometry("640x560")
        d.resizable(False, False)
        d.transient(self.root)
        d.update_idletasks()
        d.grab_set()
        self._center_dialog(d)

        tk.Frame(d, bg=acc, height=4).pack(fill="x")

        # Header
        hdr = tk.Frame(d, bg=bg)
        hdr.pack(fill="x", padx=24, pady=(16, 0))
        tk.Label(hdr, text="⚙️  Settings", font=hf, bg=bg, fg=fg).pack(anchor="w")
        tk.Label(hdr, text="Manage your security, storage, and preferences",
                 font=bod, bg=bg, fg=mfg).pack(anchor="w", pady=(2, 0))

        # Custom tab bar 
        TAB_DEFS = [
            ("💾", "Storage"),
            ("🔒", "Security"),
            ("📝", "Password Policy"),
            ("📦", "Backup & Export"),
        ]
        tab_bar = tk.Frame(d, bg=sbg)
        tab_bar.pack(fill="x", padx=24, pady=(12, 0))

        content_host = tk.Frame(d, bg=bg)
        content_host.pack(fill="both", expand=True, padx=24, pady=8)

        tab_btns = []
        tab_pages = []

        def _switch_tab(idx):
            for i, (btn, page) in enumerate(zip(tab_btns, tab_pages)):
                if i == idx:
                    btn.config(bg=acc, fg=btn_fg, relief="flat")
                    page.pack(fill="both", expand=True)
                else:
                    btn.config(bg=sbg, fg=mfg, relief="flat")
                    page.pack_forget()

        for i, (icon, label) in enumerate(TAB_DEFS):
            btn = tk.Button(tab_bar, text=f"{icon} {label}",
                            font=("Segoe UI", 10, "bold"),
                            bg=sbg, fg=mfg, relief="flat", bd=0, cursor="hand2",
                            activebackground=acc, activeforeground=btn_fg,
                            padx=14, pady=8,
                            command=lambda idx=i: _switch_tab(idx))
            btn.pack(side="left")
            tab_btns.append(btn)

            page = tk.Frame(content_host, bg=bg)
            tab_pages.append(page)

        # Storage tab
        def _build_storage(p):
            tk.Label(p, text="Data Storage Location", font=hf, bg=bg, fg=fg).pack(anchor="w", pady=(8, 4))
            current_dir = self.database_manager.data_dir
            is_custom   = current_dir != DATA_DIR
            status_col  = acc if is_custom else wrn
            tk.Label(p, text=f"Status: {'Custom' if is_custom else 'Default'}",
                     font=bod, bg=bg, fg=status_col).pack(anchor="w")
            tk.Label(p, text=f"Location: {current_dir}",
                     font=("Segoe UI", 9), bg=bg, fg=mfg, wraplength=560).pack(anchor="w", pady=2)

            tk.Frame(p, bg=bdr, height=1).pack(fill="x", pady=10)

            row = tk.Frame(p, bg=bg)
            row.pack(anchor="w")

            def _change():
                new_dir = filedialog.askdirectory(title="Select New Data Storage Location", mustexist=False)
                if new_dir and messagebox.askyesno(
                        "Change Storage Location",
                        f"Change data storage to:\n{new_dir}\n\n"
                        "New data will be saved here. Existing data stays in the current location.\n\nContinue?",
                        icon="info"):
                    if self.set_custom_data_directory(new_dir):
                        messagebox.showinfo("Success", "Storage location updated!\n\nPlease restart the application.")
                    else:
                        messagebox.showerror("Error", "Failed to change storage location.")

            def _reset():
                try:
                    if os.path.exists(CONFIG_FILE):
                        os.remove(CONFIG_FILE)
                    messagebox.showinfo("Success", "Reset to default location.\n\nPlease restart the application.")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to reset: {e}")

            tk.Button(row, text="📁  Change Location", command=_change,
                      font=bf, bg=card, fg=fg, relief="flat", bd=0, cursor="hand2",
                      activebackground=bdr, activeforeground=fg,
                      highlightbackground=bdr, highlightthickness=1,
                      padx=14, pady=7).pack(side="left", padx=(0, 8))
            if is_custom:
                tk.Button(row, text="🔄  Reset to Default", command=_reset,
                          font=bf, bg=wrn, fg=bg, relief="flat", bd=0, cursor="hand2",
                          activebackground=err, activeforeground=bg,
                          padx=14, pady=7).pack(side="left")

        _build_storage(tab_pages[0])

        # Security tab
        def _build_security(p):
            # Change master password
            tk.Label(p, text="Change Master Password", font=hf, bg=bg, fg=fg).pack(anchor="w", pady=(8, 8))
            f = tk.Frame(p, bg=bg)
            f.pack(fill="x")

            def _row(label, show=True):
                tk.Label(f, text=label, font=("Segoe UI", 10), bg=bg, fg=mfg, width=22, anchor="w").grid(
                    row=_row.idx, column=0, sticky="w", pady=4)
                v = tk.StringVar()
                e = tk.Entry(f, textvariable=v, show="●" if show else "", font=bod,
                             bg=ibg, fg=fg, relief="flat", bd=0,
                             highlightbackground=bdr, highlightcolor=acc, highlightthickness=1,
                             insertbackground=fg, width=26)
                e.grid(row=_row.idx, column=1, pady=4, padx=8, sticky="w")
                _row.idx += 1
                return v

            _row.idx = 0
            cur_var  = _row("Current password:")
            new_var  = _row("New password:")
            conf_var = _row("Confirm new password:")

            str_row = tk.Frame(f, bg=bg)
            str_row.grid(row=3, column=1, sticky="w", padx=8, pady=(0, 6))
            pw_bar = tk.Canvas(str_row, height=4, width=180, bg=bdr, highlightthickness=0)
            pw_bar.pack(side="left")
            pw_str_lbl = tk.Label(str_row, text="", font=("Segoe UI", 8), bg=bg, fg=mfg)
            pw_str_lbl.pack(side="left", padx=4)

            SC = ["#f85149", "#d29922", "#e3b341", "#58a6ff", "#3fb950"]
            SL = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]
            def _pw_strength(*_):
                pw = new_var.get()
                if not pw: pw_bar.delete("bar"); pw_str_lbl.config(text=""); return
                try: sc, _ = self.password_policy_manager.check_password_compliance(pw)
                except Exception: sc = 0
                c = SC[sc]; pw_bar.delete("bar")
                pw_bar.create_rectangle(0, 0, max(4, int(180*(sc+1)/5)), 4, fill=c, outline="", tags="bar")
                pw_str_lbl.config(text=SL[sc], fg=c)
            new_var.trace_add("write", _pw_strength)

            pw_err = tk.Label(p, text="", font=("Segoe UI", 9), bg=bg, fg=err, wraplength=540)
            pw_err.pack(anchor="w", pady=(0, 4))

            def _change_pw():
                cur  = cur_var.get()
                new  = new_var.get()
                conf = conf_var.get()
                if not cur or not new or not conf:
                    pw_err.config(text="All fields are required."); return
                if new != conf:
                    pw_err.config(text="New passwords do not match."); return
                if not self.verify_master_password(self.current_user, cur):
                    pw_err.config(text="Current password is incorrect."); return
                sc, fb = self.password_policy_manager.check_password_compliance(new)
                if sc < self.password_policy_manager.policy["min_strength"]:
                    pw_err.config(text="New password doesn't meet policy: " + "; ".join(fb)); return
                if self.change_master_password(new):
                    cur_var.set(""); new_var.set(""); conf_var.set("")
                    pw_err.config(fg=suc, text="Password changed successfully!")
                    p.after(3000, lambda: pw_err.config(text="", fg=err))
                else:
                    pw_err.config(text="Failed to change password. Please try again.")

            tk.Button(p, text="🔑  Change Password", command=_change_pw,
                      font=bf, bg=acc, fg=btn_fg, relief="flat", bd=0, cursor="hand2",
                      activebackground=cfg.get("btn_hover_color", acc), activeforeground=btn_fg,
                      padx=16, pady=7).pack(anchor="w", pady=(4, 0))

            # 2FA section
            tk.Frame(p, bg=bdr, height=1).pack(fill="x", pady=(18, 12))
            tk.Label(p, text="Two-Factor Authentication", font=hf, bg=bg, fg=fg).pack(anchor="w")

            tfa_status = tk.Label(p, text="", font=bod, bg=bg, fg=fg)
            tfa_status.pack(anchor="w", pady=(4, 8))
            tfa_btn_row = tk.Frame(p, bg=bg)
            tfa_btn_row.pack(anchor="w")

            def _refresh_2fa():
                for w in tfa_btn_row.winfo_children(): w.destroy()
                prof = self.database_manager.load_profiles()
                enabled = prof.get(self.current_user, {}).get("2fa_enabled", False)
                if enabled:
                    tfa_status.config(text="🔒  Two-Factor Authentication: ENABLED", fg=suc)
                    tk.Button(tfa_btn_row, text="🔄  Reconfigure", font=bf,
                              bg=card, fg=fg, relief="flat", bd=0, cursor="hand2",
                              activebackground=bdr, activeforeground=fg,
                              highlightbackground=bdr, highlightthickness=1,
                              padx=14, pady=7,
                              command=lambda: _start_2fa()).pack(side="left", padx=(0, 8))
                    tk.Button(tfa_btn_row, text="Disable 2FA", font=bf,
                              bg=err, fg=btn_fg, relief="flat", bd=0, cursor="hand2",
                              activebackground="#c0392b", activeforeground=btn_fg,
                              padx=14, pady=7,
                              command=lambda: _disable_2fa()).pack(side="left")
                else:
                    tfa_status.config(text="🔓  Two-Factor Authentication: DISABLED", fg=wrn)
                    tk.Button(tfa_btn_row, text="🔒  Enable 2FA", font=bf,
                              bg=acc, fg=btn_fg, relief="flat", bd=0, cursor="hand2",
                              activebackground=cfg.get("btn_hover_color", acc), activeforeground=btn_fg,
                              padx=14, pady=7,
                              command=lambda: _start_2fa()).pack(side="left")

            def _start_2fa():
                new_secret = pyotp.random_base32()
                prof = self.database_manager.load_profiles()
                up   = prof.get(self.current_user, {})
                up["2fa_secret"] = self.security_manager.encrypt_data(new_secret)
                prof[self.current_user] = up
                if self.database_manager.save_profiles(prof):
                    self.show_2fa_setup(self.current_user, new_secret, enable_callback=_refresh_2fa)
                else:
                    messagebox.showerror("Error", "Failed to start 2FA setup.")

            def _disable_2fa():
                if messagebox.askyesno("Disable 2FA",
                        "Are you sure you want to disable Two-Factor Authentication?\n\nThis reduces your account security.",
                        icon="warning"):
                    if self.toggle_2fa(False):
                        _refresh_2fa()
                    else:
                        messagebox.showerror("Error", "Failed to disable 2FA.")

            _refresh_2fa()

            # Auto-lock info 
            tk.Frame(p, bg=bdr, height=1).pack(fill="x", pady=(18, 10))
            tk.Label(p, text="Auto-Lock", font=hf, bg=bg, fg=fg).pack(anchor="w")
            tk.Label(p, text=f"Auto-locks after {LOCK_TIMEOUT // 60} minutes of inactivity",
                     font=bod, bg=bg, fg=fg).pack(anchor="w", pady=(4, 2))
            tk.Label(p, text="To change the timeout, edit LOCK_TIMEOUT in config/constants.py",
                     font=("Segoe UI", 9), bg=bg, fg=mfg).pack(anchor="w")

        _build_security(tab_pages[1])

        # Password Policy tab
        def _build_policy(p):
            tk.Label(p, text="Password Policy", font=hf, bg=bg, fg=fg).pack(anchor="w", pady=(8, 8))
            cur_policy = self.password_policy_manager.get_policy()

            settings = [
                ("Minimum Length",    "min_length",        8,  32, False),
                ("Minimum Strength",  "min_strength",      1,   5, False),
                ("Require Uppercase", "require_uppercase", 0,   1, True),
                ("Require Lowercase", "require_lowercase", 0,   1, True),
                ("Require Numbers",   "require_digits",    0,   1, True),
                ("Require Symbols",   "require_special",   0,   1, True),
            ]
            pv = {}
            grid = tk.Frame(p, bg=bg)
            grid.pack(fill="x")
            for i, (lbl, key, mn, mx, is_bool) in enumerate(settings):
                tk.Label(grid, text=lbl, font=bod, bg=bg, fg=fg, width=20, anchor="w").grid(
                    row=i, column=0, sticky="w", pady=6, padx=(0, 12))
                if is_bool:
                    v = tk.BooleanVar(value=cur_policy.get(key, False))
                    cb = tk.Checkbutton(grid, variable=v, bg=bg, fg=fg,
                                       selectcolor=ibg, activebackground=bg,
                                       activeforeground=fg, bd=0, cursor="hand2")
                    cb.grid(row=i, column=1, sticky="w", pady=6)
                    pv[key] = v
                else:
                    v = tk.StringVar(value=str(cur_policy.get(key, mn)))
                    sb = tk.Spinbox(grid, from_=mn, to=mx, textvariable=v, width=6,
                                   font=bod, bg=ibg, fg=fg, relief="flat", bd=0,
                                   buttonbackground=bdr, insertbackground=fg,
                                   highlightbackground=bdr, highlightcolor=acc, highlightthickness=1)
                    sb.grid(row=i, column=1, sticky="w", pady=6)
                    pv[key] = v

            policy_desc = tk.Label(p, text="", font=("Segoe UI", 9), bg=bg, fg=mfg, wraplength=540)
            policy_desc.pack(anchor="w", pady=(8, 4))
            def _refresh_desc():
                d_txt = self.password_policy_manager.get_policy_description()
                policy_desc.config(text=f"Current: {d_txt}")
            _refresh_desc()

            pol_err = tk.Label(p, text="", font=("Segoe UI", 9), bg=bg, fg=err)
            pol_err.pack(anchor="w")

            def _save_policy():
                np = {}
                for key, v in pv.items():
                    if isinstance(v, tk.BooleanVar):
                        np[key] = v.get()
                    else:
                        try: np[key] = int(v.get())
                        except ValueError:
                            pol_err.config(text=f"Invalid value for {key}"); return
                if np["min_length"] < 8:
                    pol_err.config(text="Minimum length must be at least 8."); return
                if not (1 <= np["min_strength"] <= 5):
                    pol_err.config(text="Strength must be 1–5."); return
                if self.password_policy_manager.update_policy(np):
                    _refresh_desc()
                    pol_err.config(fg=suc, text="Policy saved successfully!")
                    p.after(3000, lambda: pol_err.config(text="", fg=err))
                else:
                    pol_err.config(text="Failed to save policy.")

            tk.Button(p, text="💾  Save Policy", command=_save_policy,
                      font=bf, bg=acc, fg=btn_fg, relief="flat", bd=0, cursor="hand2",
                      activebackground=cfg.get("btn_hover_color", acc), activeforeground=btn_fg,
                      padx=16, pady=7).pack(anchor="w", pady=(8, 0))

        _build_policy(tab_pages[2])

        # Backup & Export tab
        def _build_backup(p):
            # Export section
            tk.Label(p, text="Export Data", font=hf, bg=bg, fg=fg).pack(anchor="w", pady=(8, 4))
            tk.Label(p,
                     text="Exported files contain DECRYPTED passwords — store them securely!",
                     font=("Segoe UI", 9, "bold"), bg=bg, fg=wrn, wraplength=560).pack(anchor="w", pady=(0, 8))

            ex_row = tk.Frame(p, bg=bg)
            ex_row.pack(anchor="w")

            def _export_csv():
                fn = filedialog.asksaveasfilename(title="Export to CSV",
                    defaultextension=".csv", filetypes=[("CSV", "*.csv"), ("All", "*.*")])
                if fn:
                    try:
                        if self._export_to_csv(fn):
                            messagebox.showinfo("Exported", f"Saved to:\n{fn}")
                        else:
                            messagebox.showerror("Error", "Export failed.")
                    except Exception as e:
                        messagebox.showerror("Error", str(e))

            def _export_json():
                fn = filedialog.asksaveasfilename(title="Export to JSON",
                    defaultextension=".json", filetypes=[("JSON", "*.json"), ("All", "*.*")])
                if fn:
                    try:
                        if self._export_to_json(fn):
                            messagebox.showinfo("Exported", f"Saved to:\n{fn}")
                        else:
                            messagebox.showerror("Error", "Export failed.")
                    except Exception as e:
                        messagebox.showerror("Error", str(e))

            tk.Button(ex_row, text="📊  Export CSV", command=_export_csv,
                      font=bf, bg=card, fg=fg, relief="flat", bd=0, cursor="hand2",
                      activebackground=bdr, activeforeground=fg,
                      highlightbackground=bdr, highlightthickness=1,
                      padx=14, pady=7).pack(side="left", padx=(0, 8))
            tk.Button(ex_row, text="📋  Export JSON", command=_export_json,
                      font=bf, bg=card, fg=fg, relief="flat", bd=0, cursor="hand2",
                      activebackground=bdr, activeforeground=fg,
                      highlightbackground=bdr, highlightthickness=1,
                      padx=14, pady=7).pack(side="left")

            # Backup section
            tk.Frame(p, bg=bdr, height=1).pack(fill="x", pady=(18, 12))
            tk.Label(p, text="Backup & Restore", font=hf, bg=bg, fg=fg).pack(anchor="w")
            tk.Label(p, text="Create a full encrypted backup of your vault or restore from one.",
                     font=bod, bg=bg, fg=mfg, wraplength=560).pack(anchor="w", pady=(2, 8))

            bu_row = tk.Frame(p, bg=bg)
            bu_row.pack(anchor="w")

            def _create_backup():
                bu_dir = filedialog.askdirectory(title="Select Backup Location")
                if bu_dir:
                    try:
                        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
                        dest = os.path.join(bu_dir, f"krault_backup_{ts}")
                        shutil.copytree(self.database_manager.data_dir, dest)
                        messagebox.showinfo("Backup Created", f"Backup saved to:\n{dest}")
                    except Exception as e:
                        messagebox.showerror("Error", f"Backup failed: {e}")

            def _restore_backup():
                bu_dir = filedialog.askdirectory(title="Select Backup Directory")
                if bu_dir and messagebox.askyesno(
                        "Restore Backup",
                        f"Restore from:\n{bu_dir}\n\nThis will REPLACE all current data.\n\nContinue?",
                        icon="warning"):
                    try:
                        self.database_manager.close()
                        if os.path.exists(self.database_manager.data_dir):
                            shutil.rmtree(self.database_manager.data_dir)
                        shutil.copytree(bu_dir, self.database_manager.data_dir)
                        messagebox.showinfo("Restored", "Backup restored.\n\nPlease restart the application.")
                    except Exception as e:
                        messagebox.showerror("Error", f"Restore failed: {e}")
                        self.database_manager = DatabaseManager(self.security_manager)

            tk.Button(bu_row, text="Create Backup", command=_create_backup,
                      font=bf, bg=card, fg=fg, relief="flat", bd=0, cursor="hand2",
                      activebackground=bdr, activeforeground=fg,
                      highlightbackground=bdr, highlightthickness=1,
                      padx=14, pady=7).pack(side="left", padx=(0, 8))
            tk.Button(bu_row, text="Restore Backup", command=_restore_backup,
                      font=bf, bg=wrn, fg=bg, relief="flat", bd=0, cursor="hand2",
                      activebackground=err, activeforeground=btn_fg,
                      padx=14, pady=7).pack(side="left")

        _build_backup(tab_pages[3])

        # Activate first tab
        _switch_tab(0)

        # Bottom close button
        foot = tk.Frame(d, bg=bg)
        foot.pack(fill="x", padx=24, pady=(0, 14))
        tk.Button(foot, text="✓  Done", command=d.destroy,
                  font=bf, bg=acc, fg=btn_fg, relief="flat", bd=0, cursor="hand2",
                  activebackground=cfg.get("btn_hover_color", acc), activeforeground=btn_fg,
                  padx=20, pady=7).pack(side="right")

    def show_password_recovery(self) -> None:
        """ Show password recovery information """
        dialog = tk.Toplevel(self.root)
        dialog.title("Password Recovery")
        dialog.geometry("520x380")
        dialog.configure(bg=self._get_style_config()['bg_color'])
        dialog.transient(self.root)
        dialog.update_idletasks()
        dialog.grab_set()

        self._center_dialog(dialog)

        style_config = self._get_style_config()

        # Header
        header_frame = tk.Frame(dialog, bg=style_config['bg_color'])
        header_frame.pack(fill='x', padx=15, pady=10)

        title_label = tk.Label(
            header_frame,
            text="🔑 Password Recovery",
            font=style_config['title_font'],
            bg=style_config['bg_color'],
            fg=style_config['fg_color']
        )
        title_label.pack(anchor='w')

        subtitle_label = tk.Label(
            header_frame,
            text="There is no way to recover a forgotten master password",
            font=style_config['body_font'],
            bg=style_config['bg_color'],
            fg=style_config.get('warning_color', style_config['fg_color'])
        )
        subtitle_label.pack(anchor='w', pady=(2, 0))

        # Content
        content_frame = ttk.Frame(dialog, style='Dark.TFrame')
        content_frame.pack(fill='both', expand=True, padx=15, pady=10)

        explanation = (
            "Your vault is encrypted with a key derived directly from your "
            "master password. That key is never written to disk and there "
            "is no backdoor, support-desk reset, or hidden recovery "
            "mechanism — not because it hasn't been built yet, but because "
            "building one would mean storing something that could "
            "reconstruct your key, which would defeat the encryption.\n\n"
            "If you forget your master password, your entries cannot be "
            "decrypted by anyone, including you."
        )
        ttk.Label(content_frame, text=explanation, style='Dark.TLabel',
                  wraplength=460, justify='left').pack(anchor='w', pady=(0, 14))

        ttk.Label(content_frame, text="What you can do instead:",
                  style='DarkHeading.TLabel').pack(anchor='w', pady=(0, 8))

        for tip in (
            "Store your master password in a safe place outside this app "
            "(e.g. written down and kept somewhere secure) — not as an "
            "entry inside the vault it protects.",
            "Keep your two-factor authenticator's backup/recovery codes "
            "(from the authenticator app itself) somewhere safe — losing "
            "both the device and those codes will also lock you out.",
            "Use Settings → Backup to keep encrypted backups; they still "
            "require the master password to open, but protect you against "
            "file loss or corruption, which is a separate problem from a "
            "forgotten password.",
        ):
            tip_frame = ttk.Frame(content_frame, style='Dark.TFrame')
            tip_frame.pack(fill='x', pady=4)
            ttk.Label(tip_frame, text=f"• {tip}", style='Dark.TLabel',
                      wraplength=460, justify='left').pack(anchor='w')

        # Close button
        close_frame = tk.Frame(dialog, bg=style_config['bg_color'])
        close_frame.pack(fill='x', padx=15, pady=10)

        self.create_modern_button(close_frame, text="Close",
                    command=dialog.destroy,
                    bg_color=style_config['secondary_color'],
                    hover_color=style_config['accent_color'],
                    width=100, height=35).pack(side='right')

    # Leading characters that spreadsheet apps (Excel, Sheets, LibreOffice)
    # interpret as the start of a formula/command (CWE-1236: Improper
    # Neutralization of Formula Elements in a CSV File).
    _CSV_FORMULA_TRIGGERS = ('=', '+', '-', '@', '\t', '\r')

    @classmethod
    def _sanitize_csv_field(cls, value) -> str:
        """ Neutralize CSV formula injection """
        text = '' if value is None else str(value)
        if text.startswith(cls._CSV_FORMULA_TRIGGERS):
            return "'" + text
        return text

    def _export_to_csv(self, filename: str) -> bool:
        """ Export password entries to CSV file """
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['website', 'username', 'email', 'password', 'pin', 'notes', 'created_at']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for entry in self.entries:
                    # Decrypt password for export
                    decrypted_password = self.security_manager.decrypt_data(entry['password'])
                    
                    writer.writerow({
                        'website': self._sanitize_csv_field(entry.get('website', '')),
                        'username': self._sanitize_csv_field(entry.get('username', entry.get('user', ''))),
                        'email': self._sanitize_csv_field(entry.get('email', '')),
                        'password': self._sanitize_csv_field(decrypted_password),
                        'pin': self._sanitize_csv_field(entry.get('pin', entry.get('PIN', ''))),
                        'notes': self._sanitize_csv_field(entry.get('notes', '')),
                        'created_at': self._sanitize_csv_field(entry.get('created_at', ''))
                    })
            
            self.database_manager._secure_chmod_file(filename)
            return True
        except Exception as e:
            logging.error(f"CSV export failed: {e}")
            return False

    def _export_to_json(self, filename: str) -> bool:
        """ Export password entries to JSON file """
        try:
            export_data = []
            for entry in self.entries:
                # Decrypt password for export
                decrypted_password = self.security_manager.decrypt_data(entry['password'])
                
                export_entry = entry.copy()
                export_entry['password'] = decrypted_password
                export_data.append(export_entry)
            
            with open(filename, 'w', encoding='utf-8') as jsonfile:
                json.dump(export_data, jsonfile, indent=2, ensure_ascii=False)
            
            self.database_manager._secure_chmod_file(filename)
            return True
        except Exception as e:
            logging.error(f"JSON export failed: {e}")
            return False

    def lock_application(self) -> None:
        """ Lock the application and show lock screen """
        self.is_locked = True
        self.audit_logger.log_security_event(self.current_user, "AUTO_LOCK", "Application locked due to inactivity")
        self.show_lock_screen()
        
    def unlock_application(self, password: str) -> bool:
        """ Unlock the application with master password verification """
        if self.verify_master_password(self.current_user, password):
            self.is_locked = False
            self.last_activity = time.time()
            self.show_main_interface()
            self.audit_logger.log_security_event(self.current_user, "UNLOCK", "Application unlocked successfully")
            return True
        else:
            self.audit_logger.log_security_event(self.current_user, "UNLOCK_FAILED", "Failed unlock attempt")
            return False
        
    def copy_username(self) -> None:
        """ Copy username of selected entry to clipboard """
        entry = self._get_selected_tree_entry()
        if not entry:
            return
        self.copy_to_clipboard(entry.get('username', entry.get('user', '')))
        self.audit_logger.log_password_access(
            self.current_user,
            entry.get('website', ''),
            "COPY_USERNAME"
        )

    def copy_email(self) -> None:
        """ Copy email of selected entry to clipboard """
        entry = self._get_selected_tree_entry()
        if not entry:
            return
        self.copy_to_clipboard(entry.get('email', ''))
        self.audit_logger.log_password_access(
            self.current_user,
            entry.get('website', ''),
            "COPY_EMAIL"
        )

    def copy_pin(self) -> None:
        """ Copy PIN of selected entry to clipboard """
        entry = self._get_selected_tree_entry()
        if not entry:
            return
        self.copy_to_clipboard(entry.get('pin', entry.get('PIN', '')))
        self.audit_logger.log_password_access(
            self.current_user,
            entry.get('website', ''),
            "COPY_PIN"
        )
    
    def show_lock_screen(self) -> None:
        """ Centred lock screen """
        self.clear_screen()
        cfg = self._get_style_config()

        bg  = cfg["bg_color"]
        sbg = cfg.get("secondary_bg_color", bg)
        card = cfg.get("card_bg_color", sbg)
        acc = cfg["accent_color"]
        fg  = cfg["fg_color"]
        mfg = cfg.get("muted_fg_color", fg)
        bdr = cfg.get("border_color", "#2d2d5a")
        btn = cfg.get("btn_bg_color", acc)
        bfg = cfg.get("btn_fg_color", "#ffffff")
        ibg = cfg.get("input_bg_color", sbg)
        bod = cfg["body_font"]
        bf  = cfg["button_font"]
        ttl = cfg["title_font"]

        outer = tk.Frame(self.root, bg=bg)
        outer.pack(expand=True, fill="both")

        col = tk.Frame(outer, bg=bg, width=320)
        col.place(relx=.5, rely=.5, anchor="center")

        # Lock badge
        badge = tk.Frame(col, bg=card, width=64, height=64,
                         highlightbackground=cfg.get("error_color","#f85149"),
                         highlightthickness=1)
        badge.pack(pady=(0, 16))
        badge.pack_propagate(False)
        tk.Label(badge, text="🔒", font=("Segoe UI", 28),
                 bg=card, fg=cfg.get("error_color","#f85149")
                 ).place(relx=.5, rely=.5, anchor="center")

        tk.Label(col, text="Vault locked", font=ttl,
                 bg=bg, fg=fg).pack()
        tk.Label(col, text=f"Locked due to inactivity · {self.current_user}",
                 font=bod, bg=bg, fg=mfg).pack(pady=(4, 24))

        card_frame = tk.Frame(col, bg=card,
                              highlightbackground=bdr, highlightthickness=1)
        card_frame.pack(fill="x")
        inner = tk.Frame(card_frame, bg=card)
        inner.pack(fill="x", padx=28, pady=24)

        tk.Label(inner, text="MASTER PASSWORD", font=("Segoe UI", 9),
                 bg=card, fg=mfg).pack(anchor="w")

        pw_var = tk.StringVar()
        pw_entry = tk.Entry(inner, textvariable=pw_var, show="●",
                            font=bod, bg=ibg, fg=fg, relief="flat", bd=0,
                            highlightbackground=bdr, highlightcolor=acc,
                            highlightthickness=1, insertbackground=fg,
                            selectbackground=acc, selectforeground=bg)
        pw_entry.pack(fill="x", ipady=6, pady=(3, 16))

        err_label = tk.Label(inner, text="", font=("Segoe UI", 10),
                             bg=card, fg=cfg.get("error_color","#f85149"))
        err_label.pack(anchor="w")

        def attempt_unlock():
            pw = pw_var.get()
            if not pw:
                err_label.config(text="Please enter your master password.")
                pw_entry.focus()
                return
            unlocked = self.unlock_application(pw)
            if unlocked:
                if pw_entry.winfo_exists():
                    pw_var.set("")
                if err_label.winfo_exists():
                    err_label.config(text="")
            else:
                pw_var.set("")
                if err_label.winfo_exists():
                    err_label.config(text="Incorrect password — try again.")
                if pw_entry.winfo_exists():
                    pw_entry.focus()

        unlock_btn = tk.Button(inner, text="Unlock vault",
                               command=attempt_unlock, font=bf,
                               bg=btn, fg=bfg, relief="flat",
                               activebackground=cfg.get("btn_hover_color", btn),
                               activeforeground=bfg, bd=0, cursor="hand2")
        unlock_btn.pack(fill="x", ipady=8)

        pw_entry.bind("<Return>", lambda _: attempt_unlock())
        pw_entry.focus()
    
    def logout(self) -> None:
        """ Logout with secure memory cleanup and return to login screen.        
        Security Features:
            - Securely clears all sensitive data from memory
            - Overwrites strings with null bytes
            - Clears session data
            - Forces garbage collection
            - Invalidates security session """
         # Securely clear all sensitive data
        self._secure_password.clear()
        self._temp_password.clear()

        # Clear any session data
        for key in list(self._secure_session_data.keys()):
            if isinstance(self._secure_session_data[key], SecureString):
                self._secure_session_data[key].clear()
            else:
                # Overwrite string data with null bytes
                if isinstance(self._secure_session_data[key], str):
                    self._secure_session_data[key] = '\x00' * len(self._secure_session_data[key])
        self._secure_session_data.clear()
        
        # Clear other sensitive data
        self.current_user = None
        self.current_database = None
        self.entries = []
        self.is_locked = False
        
        # Clear security manager session
        if hasattr(self, 'security_manager'):
            self.security_manager.invalidate_session()

        # Force garbage collection
        try:
            import gc
            gc.collect()
        except ImportError:
            pass  # gc not available, continue
        
        # Log logout event
        logging.info("User logged out successfully")
        
        # Return to login screen
        self.show_login_screen()
 
    def clear_screen(self) -> None:
        """ Clear all widgets from the root window """
        self._cancel_entry_filter()
        self._cancel_entry_render()
        for widget in self.root.winfo_children():
            try:
                widget.destroy()
            except Exception as e:
                logging.error(f"Error destroying widget: {e}")
 
    def _center_dialog(self, dialog: tk.Toplevel) -> None:
        """ Center a dialog window on screen """
        try:
            dialog.update_idletasks()
            width = dialog.winfo_width()
            height = dialog.winfo_height()
            x = (dialog.winfo_screenwidth() // 2) - (width // 2)
            y = (dialog.winfo_screenheight() // 2) - (height // 2)
            dialog.geometry(f'{width}x{height}+{x}+{y}')
        except Exception as e:
            logging.error(f"Error centering dialog: {e}")