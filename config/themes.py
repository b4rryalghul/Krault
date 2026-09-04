"""Theme system for Kristen Guard password manager."""
import json
import logging
import os
import tkinter as tk
from typing import Dict, Any, Optional

from config.constants import DATA_DIR, THEME_CONFIG_FILE


class ModernThemeManager:
    """Manages the four built-in application themes """

    AVAILABLE_THEMES = ["midnight", "light", "ocean", "forest"]

    def __init__(self) -> None:
        self._themes: Dict[str, Dict[str, Any]] = {
            "midnight": self._midnight(),
            "light":    self._light(),
            "ocean":    self._ocean(),
            "forest":   self._forest(),
        }
        self.current_theme: str = self._load_saved_theme() or "midnight"

    # Theme definitions
    def _midnight(self) -> Dict[str, Any]:
        return {
            "name": "Midnight Pro",
            # Backgrounds
            "bg_color":           "#0f0f23",
            "secondary_bg_color": "#1a1a2e",
            "card_bg_color":      "#16213e",
            "input_bg_color":     "#0f0f23",
            # Accents
            "accent_color":       "#7b68ee",
            "secondary_color":    "#00d4ff",
            # Semantic
            "error_color":        "#f85149",
            "warning_color":      "#d29922",
            "success_color":      "#3fb950",
            # Text
            "fg_color":           "#e8e8ff",
            "muted_fg_color":     "#8888b8",
            # Borders & disabled
            "border_color":       "#2d2d5a",
            "disabled_color":     "#4a4a6a",
            "shadow_color":       "#000000",
            "highlight_color":    "#302b4d",
            # Button
            "btn_bg_color":       "#452bd6",
            "btn_hover_color":    "#5a3de8",
            "btn_fg_color":       "#ffffff",
            # Typography — Segoe UI on Windows, SF Pro on macOS, fallbacks elsewhere
            "title_font":         ("Segoe UI", 20, "bold"),
            "heading_font":       ("Segoe UI", 14, "bold"),
            "subheading_font":    ("Segoe UI", 12, "bold"),
            "body_font":          ("Segoe UI", 11),
            "small_font":         ("Segoe UI", 10),
            "monospace_font":     ("Cascadia Code", 10),
            "button_font":        ("Segoe UI", 11, "bold"),
            "label_font":         ("Segoe UI", 10),
            # Shape
            "border_radius":      10,
            "card_radius":        14,
            "input_radius":       8,
            "hover_lighten":      15,
        }

    def _light(self) -> Dict[str, Any]:
        return {
            "name": "Arctic Light",
            "bg_color":           "#f0f4ff",
            "secondary_bg_color": "#ffffff",
            "card_bg_color":      "#ffffff",
            "input_bg_color":     "#f8faff",
            "accent_color":       "#4361ee",
            "secondary_color":    "#7209b7",
            "error_color":        "#e63946",
            "warning_color":      "#ff9e00",
            "success_color":      "#2a9d8f",
            "fg_color":           "#2b2d42",
            "muted_fg_color":     "#6c757d",
            "border_color":       "#dde3f0",
            "disabled_color":     "#adb5bd",
            "shadow_color":       "#111010",
            "highlight_color":    "#1d223a",
            "btn_bg_color":       "#4361ee",
            "btn_hover_color":    "#3451d1",
            "btn_fg_color":       "#ffffff",
            "title_font":         ("Segoe UI", 20, "bold"),
            "heading_font":       ("Segoe UI", 14, "bold"),
            "subheading_font":    ("Segoe UI", 12, "bold"),
            "body_font":          ("Segoe UI", 11),
            "small_font":         ("Segoe UI", 10),
            "monospace_font":     ("Consolas", 10),
            "button_font":        ("Segoe UI", 11, "bold"),
            "label_font":         ("Segoe UI", 10),
            "border_radius":      10,
            "card_radius":        14,
            "input_radius":       8,
            "hover_lighten":      -10,
        }

    def _ocean(self) -> Dict[str, Any]:
        return {
            "name": "Ocean Blue",
            "bg_color":           "#0a192f",
            "secondary_bg_color": "#112240",
            "card_bg_color":      "#1d3b53",
            "input_bg_color":     "#0a192f",
            "accent_color":       "#64ffda",
            "secondary_color":    "#57cbff",
            "error_color":        "#f85149",
            "warning_color":      "#d29922",
            "success_color":      "#3fb950",
            "fg_color":           "#ccd6f6",
            "muted_fg_color":     "#8892b0",
            "border_color":       "#233554",
            "disabled_color":     "#4a5568",
            "shadow_color":       "#0C0C0C",
            "highlight_color":    "#192724",
            "btn_bg_color":       "#64ffda",
            "btn_hover_color":    "#4de8c3",
            "btn_fg_color":       "#0a192f",
            "title_font":         ("Segoe UI", 20, "bold"),
            "heading_font":       ("Segoe UI", 14, "bold"),
            "subheading_font":    ("Segoe UI", 12, "bold"),
            "body_font":          ("Segoe UI", 11),
            "small_font":         ("Segoe UI", 10),
            "monospace_font":     ("Cascadia Code", 10),
            "button_font":        ("Segoe UI", 11, "bold"),
            "label_font":         ("Segoe UI", 10),
            "border_radius":      10,
            "card_radius":        14,
            "input_radius":       8,
            "hover_lighten":      15,
        }

    def _forest(self) -> Dict[str, Any]:
        return {
            "name": "Forest Green",
            "bg_color":           "#0d1b1e",
            "secondary_bg_color": "#1a2e2e",
            "card_bg_color":      "#243a3a",
            "input_bg_color":     "#0d1b1e",
            "accent_color":       "#83e85a",
            "secondary_color":    "#38b2ac",
            "error_color":        "#fc5c7d",
            "warning_color":      "#d29922",
            "success_color":      "#3fb950",
            "fg_color":           "#e8f4f4",
            "muted_fg_color":     "#7aaeae",
            "border_color":       "#2d4a4a",
            "disabled_color":     "#4a6a6a",
            "shadow_color":       "#000000",
            "highlight_color":    "#1a2018",
            "btn_bg_color":       "#83e85a",
            "btn_hover_color":    "#6dd147",
            "btn_fg_color":       "#0d1b1e",
            "title_font":         ("Segoe UI", 20, "bold"),
            "heading_font":       ("Segoe UI", 14, "bold"),
            "subheading_font":    ("Segoe UI", 12, "bold"),
            "body_font":          ("Segoe UI", 11),
            "small_font":         ("Segoe UI", 10),
            "monospace_font":     ("Cascadia Code", 10),
            "button_font":        ("Segoe UI", 11, "bold"),
            "label_font":         ("Segoe UI", 10),
            "border_radius":      10,
            "card_radius":        14,
            "input_radius":       8,
            "hover_lighten":      15,
        }

    # Public API
    def get_theme_config(self, theme_name: Optional[str] = None) -> Dict[str, Any]:
        """Return the config dict for *theme_name* or the current theme """
        name = theme_name if theme_name in self._themes else self.current_theme
        return self._themes[name].copy()

    def set_theme(self, theme_name: str) -> bool:
        """ Switch the active theme and persist the preference """
        if theme_name not in self._themes:
            logging.warning(f"Unknown theme '{theme_name}' — ignoring")
            return False
        self.current_theme = theme_name
        return self._save_theme(theme_name)

    def get_current_theme(self) -> str:
        return self.current_theme

    def get_available_themes(self):
        return list(self._themes.keys())

    def apply_ttk_styles(self, root: tk.Tk) -> None:
        """ Configure ttk widget styles to match the current theme """
        from tkinter import ttk
        cfg = self.get_theme_config()
        style = ttk.Style(root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        bg  = cfg["bg_color"]
        sbg = cfg["secondary_bg_color"]
        acc = cfg["accent_color"]
        fg  = cfg["fg_color"]
        mfg = cfg["muted_fg_color"]
        bdr = cfg["border_color"]
        sel = cfg["accent_color"]
        err = cfg["error_color"]

        style.configure(".",
            background=bg, foreground=fg,
            fieldbackground=cfg["input_bg_color"],
            bordercolor=bdr, darkcolor=sbg, lightcolor=sbg,
            troughcolor=sbg, selectbackground=acc, selectforeground=bg,
            font=cfg["body_font"])

        style.configure("TFrame", background=bg)
        style.configure("TLabel", background=bg, foreground=fg)
        style.configure("TButton",
            background=cfg["btn_bg_color"], foreground=cfg["btn_fg_color"],
            font=cfg["button_font"], relief="flat", borderwidth=0, padding=(14, 8))
        style.map("TButton",
            background=[("active", cfg["btn_hover_color"]), ("disabled", cfg["disabled_color"])],
            foreground=[("disabled", mfg)])

        style.configure("TEntry",
            fieldbackground=cfg["input_bg_color"], foreground=fg,
            insertcolor=fg, bordercolor=bdr, lightcolor=bdr, darkcolor=bdr,
            selectbackground=acc, selectforeground=bg, font=cfg["body_font"])
        style.map("TEntry", bordercolor=[("focus", acc)])

        style.configure("TNotebook", background=sbg, borderwidth=0)
        style.configure("TNotebook.Tab",
            background=sbg, foreground=mfg, padding=(14, 6), font=cfg["body_font"])
        style.map("TNotebook.Tab",
            background=[("selected", bg)], foreground=[("selected", fg)])

        style.configure("Treeview",
            background=sbg, foreground=fg, fieldbackground=sbg,
            rowheight=36, font=cfg["body_font"])
        style.map("Treeview",
            background=[("selected", acc)], foreground=[("selected", bg)])
        style.configure("Treeview.Heading",
            background=bg, foreground=mfg, relief="flat", font=cfg["label_font"])

        style.configure("Vertical.TScrollbar",
            background=sbg, troughcolor=bg,
            arrowcolor=mfg, bordercolor=bg, darkcolor=sbg, lightcolor=sbg)

    # Persistence
    def _load_saved_theme(self) -> Optional[str]:
        try:
            if os.path.exists(THEME_CONFIG_FILE):
                with open(THEME_CONFIG_FILE, "r", encoding="utf-8") as f:
                    saved = json.load(f).get("theme")
                if saved in self._themes:
                    return saved
        except Exception as e:
            logging.warning(f"Could not load saved theme: {e}")
        return None

    def _save_theme(self, theme_name: str) -> bool:
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
            with open(THEME_CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump({"theme": theme_name, "version": "2.0"}, f, indent=2)
            return True
        except Exception as e:
            logging.error(f"Could not save theme preference: {e}")
            return False


# Module-level helpers

_manager = ModernThemeManager()


def get_style_config(theme_name: Optional[str] = None) -> Dict[str, Any]:
    return _manager.get_theme_config(theme_name)


def set_application_theme(theme_name: str) -> bool:
    return _manager.set_theme(theme_name)


def get_current_theme() -> str:
    return _manager.get_current_theme()


def get_available_themes():
    return _manager.get_available_themes()


def apply_ttk_styles(root: tk.Tk) -> None:
    _manager.apply_ttk_styles(root)