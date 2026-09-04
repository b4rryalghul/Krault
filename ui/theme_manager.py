import tkinter as tk
from tkinter import ttk, messagebox, filedialog

class ThemeManager:
    def __init__(self, root):
        self.root = root
    
    def _get_style_config(self) -> dict[str, any]:
        """
        Color Scheme:
            - bg_color: Primary background (#1e1e1e - dark gray)
            - secondary_bg_color: Input fields (#2e2e2e - lighter gray)
            - accent_color: Primary actions (#4CAF50 - green)
            - secondary_color: Secondary actions (#2196F3 - blue)
            - error_color: Errors/warnings (#f44336 - red)
            - warning_color: Caution elements (#ff9800 - orange)
            - fg_color: Text color (#ffffff - white)
            - border_color: Borders/separators (#404040 - medium gray)
            - disabled_color: Disabled elements (#666666 - gray)
        """
        return {
            'bg_color': '#1e1e1e',
            'secondary_bg_color': '#2e2e2e',
            'accent_color': '#4CAF50',
            'secondary_color': '#2196F3',
            'error_color': '#f44336',
            'warning_color': '#ff9800',
            'fg_color': '#ffffff',
            'border_color': '#404040',
            'disabled_color': '#666666',
            'title_font': ('Comic Sans MS', 16, 'bold'),
            'heading_font': ('Comic Sans MS', 12, 'bold'),
            'body_font': ('Comic Sans MS', 10),
            'monospace_font': ('Comic Sans MS', 10)
        }
        
    def configure_dark_theme(self) -> None:
        """ Dark theme for all UI elements """
        try:
            style_config = self._get_style_config()
            style = ttk.Style()
            
            available_themes = style.theme_names()
            print(f"Available themes: {list(available_themes)}")
            
            preferred_themes = ['clam', 'alt', 'default']
            selected_theme = 'default'
            
            for theme in preferred_themes:
                if theme in available_themes:
                    selected_theme = theme
                    break
                    
            style.theme_use(selected_theme)
            print(f"Using theme: {selected_theme}")
            
            # Configure the root window
            self.root.configure(bg=style_config['bg_color'])
            
            # Configure ALL ttk styles
            self._configure_ttk_styles(style, style_config)
            
            # Configure basic tk options for non-ttk widgets
            self._configure_tk_widgets(style_config)
            
            print("Dark theme configured completely")
            
        except Exception as e:
            print(f"Theme configuration error: {e}")

    def _configure_ttk_styles(self, style: ttk.Style, style_config: dict[str, any]) -> None:
        """ Configure ttk widget styles for dark theme """
        # Frame styles
        style.configure('TFrame', 
                    background=style_config['bg_color'])
        style.configure('Dark.TFrame', 
                    background=style_config['bg_color'])
        
        # Label styles - configure both general and specific
        style.configure('TLabel',
                    background=style_config['bg_color'],
                    foreground=style_config['fg_color'],
                    font=style_config['body_font'])
        style.configure('Dark.TLabel',
                    background=style_config['bg_color'],
                    foreground=style_config['fg_color'],
                    font=style_config['body_font'])
        
        style.configure('DarkTitle.TLabel',
                    background=style_config['bg_color'],
                    foreground=style_config['fg_color'],
                    font=style_config['title_font'])
        
        style.configure('DarkHeading.TLabel',
                    background=style_config['bg_color'],
                    foreground=style_config['fg_color'],
                    font=style_config['heading_font'])
        
        # Entry styles
        style.configure('TEntry',
                    fieldbackground=style_config['secondary_bg_color'],
                    foreground=style_config['fg_color'],
                    insertcolor=style_config['fg_color'],
                    bordercolor=style_config['border_color'],
                    lightcolor=style_config['border_color'],
                    darkcolor=style_config['border_color'],
                    focuscolor=style_config['accent_color'])
        style.configure('Dark.TEntry',
                    fieldbackground=style_config['secondary_bg_color'],
                    foreground=style_config['fg_color'],
                    insertcolor=style_config['fg_color'],
                    bordercolor=style_config['border_color'],
                    lightcolor=style_config['border_color'],
                    darkcolor=style_config['border_color'],
                    focuscolor=style_config['accent_color'])
        
        # Map entries for different states
        style.map('TEntry',
                fieldbackground=[('readonly', style_config['secondary_bg_color']),
                                ('disabled', style_config['disabled_color']),
                                ('active', style_config['secondary_bg_color'])],
                foreground=[('disabled', style_config['disabled_color'])],
                background=[('readonly', style_config['secondary_bg_color'])])
        
        style.map('Dark.TEntry',
                fieldbackground=[('readonly', style_config['secondary_bg_color']),
                                ('disabled', style_config['disabled_color']),
                                ('active', style_config['secondary_bg_color'])],
                foreground=[('disabled', style_config['disabled_color'])],
                background=[('readonly', style_config['secondary_bg_color'])])
        
        # NOTEBOOK (Tabs)
        style.configure('TNotebook',
                    background=style_config['bg_color'],
                    tabmargins=[2, 5, 2, 0])
        style.configure('TNotebook.Tab',
                    background=style_config['secondary_bg_color'],
                    foreground=style_config['fg_color'],
                    padding=[15, 5],
                    focuscolor=style_config['accent_color'])
        
        style.map('TNotebook.Tab',
                background=[('selected', style_config['accent_color']),
                        ('active', style_config['secondary_color']),
                        ('!selected', style_config['secondary_bg_color'])],
                foreground=[('selected', style_config['fg_color']),
                        ('active', style_config['fg_color']),
                        ('!selected', style_config['fg_color'])])
        
        style.configure('Dark.TNotebook',
                    background=style_config['bg_color'],
                    tabmargins=[2, 5, 2, 0])
        style.configure('Dark.TNotebook.Tab',
                    background=style_config['secondary_bg_color'],
                    foreground=style_config['fg_color'],
                    padding=[15, 5],
                    focuscolor=style_config['accent_color'])
        
        style.map('Dark.TNotebook.Tab',
                background=[('selected', style_config['accent_color']),
                        ('active', style_config['secondary_color']),
                        ('!selected', style_config['secondary_bg_color'])],
                foreground=[('selected', style_config['fg_color']),
                        ('active', style_config['fg_color']),
                        ('!selected', style_config['fg_color'])])
        
        # Treeview styles
        style.configure('Dark.Treeview',
                      background=style_config['secondary_bg_color'],
                      foreground=style_config['fg_color'],
                      fieldbackground=style_config['secondary_bg_color'],
                      borderwidth=0)
        
        style.map('Dark.Treeview',
                background=[('selected', style_config['accent_color'])],
                foreground=[('selected', style_config['fg_color'])])
        
        # Treeview heading
        style.configure('Dark.Treeview.Heading',
                      background=style_config['secondary_bg_color'],
                      foreground=style_config['fg_color'],
                      relief='flat')
        
        style.map('Dark.Treeview.Heading',
                background=[('active', style_config['secondary_color'])])
        
        # Checkbutton styles
        style.configure('Dark.TCheckbutton',
                    background=style_config['bg_color'],
                    foreground=style_config['fg_color'],
                    indicatorbackground=style_config['secondary_bg_color'],
                    indicatorforeground=style_config['accent_color'],
                    focuscolor=style_config['accent_color'])

        style.map('Dark.TCheckbutton',
                background=[('active', style_config['bg_color']),
                            ('pressed', style_config['bg_color']),
                            ('selected', style_config['bg_color'])],
                foreground=[('active', style_config['fg_color']),
                            ('pressed', style_config['fg_color']),
                            ('selected', style_config['fg_color'])],
                indicatorbackground=[('selected', style_config['accent_color']),
                                    ('!selected', style_config['secondary_bg_color']),
                                    ('active', style_config['secondary_bg_color']),
                                    ('pressed', style_config['secondary_bg_color'])],
                indicatorforeground=[('selected', style_config['fg_color']),
                                    ('!selected', style_config['fg_color']),
                                    ('active', style_config['fg_color']),
                                    ('pressed', style_config['fg_color'])])
        
        # Spinbox style
        style.configure('Dark.TSpinbox',
                       fieldbackground=style_config['secondary_bg_color'],
                       background=style_config['secondary_bg_color'],
                       foreground=style_config['fg_color'],
                       arrowcolor=style_config['fg_color'],
                       bordercolor=style_config['border_color'])

    def refresh_theme(self) -> None:
        """ Force refresh all widgets to apply theme changes """
        # Update all existing widgets
        for widget in self.root.winfo_children():
            try:
                widget.update()
            except Exception as e:
                logging.debug(f"Could not update widget: {e}")

    