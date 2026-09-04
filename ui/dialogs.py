"""Dialog managers and dialog creation"""
import tkinter as tk
from tkinter import ttk, messagebox
import logging
from typing import Optional, Dict, Callable, Any, List

from config.themes import get_style_config
from ui.widgets import RoundedButton

class EntryDialogManager:
    """ Manages password entry dialogs to reduce code duplication and ensure consistency """
    
    def __init__(self, root: tk.Tk, style_config: Dict[str, Any], 
                 security_manager: 'SecurityManager', 
                 database_manager: 'DatabaseManager', 
                 audit_logger: 'AuditLogger'):
        """ Initialize EntryDialogManager with required dependencies """
        self.root = root
        self.style_config = style_config
        self.security_manager = security_manager
        self.database_manager = database_manager
        self.audit_logger = audit_logger
        
    def create_entry_dialog(self, title: str, entry_data: Optional[Dict[str, str]] = None, 
                          save_callback: Optional[Callable] = None) -> tk.Toplevel:
        """ Unified entry dialog for add/edit operations            
        Dialog Contents:
            -Website/Application field (required)
            -Username field (required)  
            -Password field with show/hide toggle
            -Password strength indicator
            -Generate password button
            -Save/Cancel buttons """
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.geometry("350x350")
        dialog.configure(bg=self.style_config['bg_color'])
        dialog.transient(self.root)  # Keep above parent
        dialog.grab_set()  # Modal dialog
        
        self._center_dialog(dialog)
        
        # Initialize entry data if none provided (new entry)
        if entry_data is None:
            entry_data = {'website': '', 'username': '', 'password': ''}
        
        # Apply comprehensive dark theme to all widgets
        self._configure_dark_theme_styles()
        
        # Website field
        ttk.Label(dialog, text="Website/Application:*", 
                style='Dark.TLabel').pack(pady=5)
        website_var = tk.StringVar(value=entry_data['website'])
        website_entry = ttk.Entry(dialog, textvariable=website_var, width=35, 
                                style='Dark.TEntry', font=self.style_config['body_font'])
        website_entry.pack(pady=5)
        
        # Username field
        ttk.Label(dialog, text="Username/email:*", 
                style='Dark.TLabel').pack(pady=5)
        username_var = tk.StringVar(value=entry_data['username'])
        username_entry = ttk.Entry(dialog, textvariable=username_var, width=35, 
                                style='Dark.TEntry', font=self.style_config['body_font'])
        username_entry.pack(pady=5)
        
        # Password field with show/hide toggle
        ttk.Label(dialog, text="Password:*", 
                style='Dark.TLabel').pack(pady=5)
        password_frame = ttk.Frame(dialog, style='Dark.TFrame')
        password_frame.pack(pady=5)
        
        password_var = tk.StringVar(value=entry_data['password'])
        password_entry = ttk.Entry(password_frame, textvariable=password_var, 
                                show='*', width=25, style='Dark.TEntry', 
                                font=self.style_config['body_font'])
        password_entry.pack(side='left')
        
        reveal_var = tk.BooleanVar()
        reveal_cb = ttk.Checkbutton(password_frame, text="Show", variable=reveal_var,
                                style='Dark.TCheckbutton',
                                command=lambda: self._toggle_password_visibility(
                                    password_entry, reveal_var.get()))
        reveal_cb.pack(side='left', padx=20)
        
        # Strength indicator
        strength_frame = ttk.Frame(dialog, style='Dark.TFrame')
        strength_frame.pack(pady=5)
        
        ttk.Label(strength_frame, text="Strength:", 
                style='Dark.TLabel').pack(side='left')
        strength_label = ttk.Label(strength_frame, text="", 
                                style='Dark.TLabel')
        strength_label.pack(side='left', padx=5)
        
        # Generate password button
        RoundedButton(dialog, text="Generate Strong Password", 
                    command=lambda: self._generate_and_set_password(password_var),
                    bg_color=self.style_config['accent_color'],
                    fg_color=self.style_config['fg_color'],
                    hover_color=self.style_config['secondary_color'],
                    width=200, height=35).pack(pady=5)
        
        # Update strength indicator on password change
        password_var.trace('w', lambda *args: self._update_strength_indicator(
            password_var.get(), strength_label))
        
        # Initial strength update
        self._update_strength_indicator(password_var.get(), strength_label)
        
        def handle_save():
            """Handle save button click with validation."""
            if save_callback:
                # Validate required fields
                if not website_var.get().strip():
                    messagebox.showerror("Error", "Website/Application is required!")
                    website_entry.focus()
                    return
                if not username_var.get().strip():
                    messagebox.showerror("Error", "Username is required!")
                    username_entry.focus()
                    return
                if not password_var.get():
                    messagebox.showerror("Error", "Password is required!")
                    password_entry.focus()
                    return
                    
                save_callback({
                    'website': website_var.get().strip(),
                    'username': username_var.get().strip(),
                    'password': password_var.get()
                })
            dialog.destroy()
                
        button_frame = ttk.Frame(dialog, style='Dark.TFrame')
        button_frame.pack(pady=20)
        
        # Save and Cancel buttons
        RoundedButton(button_frame, text="Save", command=handle_save,
                    bg_color=self.style_config['accent_color'],
                    fg_color=self.style_config['fg_color'],
                    hover_color=self.style_config['secondary_color'],
                    width=100, height=35).pack(side='left', padx=10)
                    
        RoundedButton(button_frame, text="Cancel", command=dialog.destroy,
                    bg_color=self.style_config['error_color'],
                    fg_color=self.style_config['fg_color'],
                    hover_color=self.style_config['warning_color'],
                    width=100, height=35).pack(side='left', padx=10)
        
        website_entry.focus()
        return dialog

    def _configure_dark_theme_styles(self) -> None:
        """ Configure comprehensive dark theme styles for ttk widgets """
        style = ttk.Style()
        
        # Configure base styles
        style.configure('Dark.TFrame', 
                       background=self.style_config['bg_color'])
        
        style.configure('Dark.TLabel',
                       background=self.style_config['bg_color'],
                       foreground=self.style_config['fg_color'],
                       font=self.style_config['body_font'])
        
        style.configure('Dark.TEntry',
                       fieldbackground=self.style_config['secondary_bg_color'],
                       background=self.style_config['secondary_bg_color'],
                       foreground=self.style_config['fg_color'],
                       insertcolor=self.style_config['fg_color'],  # Cursor color
                       bordercolor=self.style_config['border_color'],
                       focuscolor=self.style_config['accent_color'])
        
        # Checkbutton style
        style.configure('Dark.TCheckbutton',
                    background=self.style_config['bg_color'],
                    foreground=self.style_config['fg_color'],
                    indicatorbackground=self.style_config['secondary_bg_color'],
                    indicatorforeground=self.style_config['accent_color'],
                    focuscolor=self.style_config['accent_color'])

        style.map('Dark.TCheckbutton',
                background=[('active', self.style_config['bg_color']),
                            ('pressed', self.style_config['bg_color']),
                            ('selected', self.style_config['bg_color'])],
                foreground=[('active', self.style_config['fg_color']),
                            ('pressed', self.style_config['fg_color']),
                            ('selected', self.style_config['fg_color'])],
                indicatorbackground=[('selected', self.style_config['accent_color']),
                                    ('!selected', self.style_config['secondary_bg_color']),
                                    ('active', self.style_config['secondary_bg_color']),
                                    ('pressed', self.style_config['secondary_bg_color'])],
                indicatorforeground=[('selected', self.style_config['fg_color']),
                                    ('!selected', self.style_config['fg_color']),
                                    ('active', self.style_config['fg_color']),
                                    ('pressed', self.style_config['fg_color'])])
        
        # Combobox style
        style.configure('Dark.TCombobox',
                       fieldbackground=self.style_config['secondary_bg_color'],
                       background=self.style_config['secondary_bg_color'],
                       foreground=self.style_config['fg_color'],
                       arrowcolor=self.style_config['fg_color'],
                       bordercolor=self.style_config['border_color'],
                       focuscolor=self.style_config['accent_color'])
        
        style.map('Dark.TCombobox',
                 fieldbackground=[('readonly', self.style_config['secondary_bg_color'])],
                 background=[('readonly', self.style_config['secondary_bg_color'])],
                 foreground=[('readonly', self.style_config['fg_color'])])
        
        # Button style
        style.configure('Dark.TButton',
                       background=self.style_config['accent_color'],
                       foreground=self.style_config['fg_color'],
                       focuscolor=self.style_config['accent_color'])
        
        style.map('Dark.TButton',
                 background=[('active', self.style_config['secondary_color']),
                            ('pressed', self.style_config['secondary_color'])])
        
        # Scrollbar style
        style.configure('Dark.Vertical.TScrollbar',
                       background=self.style_config['secondary_bg_color'],
                       darkcolor=self.style_config['secondary_bg_color'],
                       lightcolor=self.style_config['secondary_bg_color'],
                       troughcolor=self.style_config['bg_color'],
                       bordercolor=self.style_config['bg_color'],
                       arrowcolor=self.style_config['fg_color'])
        
        style.map('Dark.Vertical.TScrollbar',
                 background=[('active', self.style_config['accent_color'])])
        
    def _toggle_password_visibility(self, password_entry: ttk.Entry, show: bool) -> None:
        """ Toggle password visibility in entry field """
        try:
            if show:
                password_entry.configure(show='')  # Show plain text
            else:
                password_entry.configure(show='*')  # Show asterisks
        except Exception as e:
            logging.error(f"Error toggling password visibility: {e}")
    
    def _generate_and_set_password(self, password_var: tk.StringVar) -> None:
        """ Generate a strong password and set it in the entry field
        Password Generation:
            -16 characters length
            -Mix of uppercase, lowercase, digits, and special characters
            -Cryptographically secure random selection
            -Guarantees at least one of each required character type            
        Security Features:
            -Uses secrets module for cryptographically secure randomness
            -Ensures password meets common strength requirements """
        try:
            length = 16
            # Character sets for guaranteed inclusion
            uppercase = string.ascii_uppercase
            lowercase = string.ascii_lowercase
            digits = string.digits
            special = "!@#$%^&*"
            
            # Ensure at least one of each type
            password_chars = [
                secrets.choice(uppercase),
                secrets.choice(lowercase),
                secrets.choice(digits),
                secrets.choice(special)
            ]
            
            # Fill the rest with random characters from all sets
            all_chars = uppercase + lowercase + digits + special
            password_chars.extend(secrets.choice(all_chars) for _ in range(length - 4))
            
            # Shuffle to randomize positions
            secrets.SystemRandom().shuffle(password_chars)
            password = ''.join(password_chars)
            
            password_var.set(password)
        except Exception as e:
            logging.error(f"Error generating password: {e}")
            messagebox.showerror("Error", "Failed to generate password")
    
    def _update_strength_indicator(self, password: str, strength_label: ttk.Label) -> None:
        """ Update password strength indicator with color coding
        Strength Levels:
            -Very Weak (red): < 8 characters or common password
            -Weak (orange): 8+ characters only
            -Fair (yellow): + uppercase/lowercase mix
            -Good (light green): + numbers
            -Strong (green): + special characters """
        try:
            if not password:
                strength_label.configure(text="", foreground=self.style_config['fg_color'])
                return
                
            score = 0
            if len(password) >= 8:
                score += 1
            if any(c.isupper() for c in password) and any(c.islower() for c in password):
                score += 1
            if any(c.isdigit() for c in password):
                score += 1
            if any(not c.isalnum() for c in password):
                score += 1
                
            strength_texts = ["Very Weak", "Weak", "Fair", "Good", "Strong"]
            colors = [self.style_config['error_color'], "#ff9800", "#ffc107", "#8bc34a", "#4caf50"]
            
            strength_label.configure(
                text=strength_texts[score],
                foreground=colors[score]
            )
        except Exception as e:
            logging.error(f"Error updating strength indicator: {e}")
    
    def _center_dialog(self, dialog: tk.Toplevel) -> None:
        """ Center dialog relative to parent window """
        try:
            dialog.update_idletasks()  # Ensure window dimensions are calculated
            width = dialog.winfo_width()
            height = dialog.winfo_height()
            x = (dialog.winfo_screenwidth() // 2) - (width // 2)
            y = (dialog.winfo_screenheight() // 2) - (height // 2)
            dialog.geometry(f'{width}x{height}+{x}+{y}')
        except Exception as e:
            logging.error(f"Error centering dialog: {e}")
