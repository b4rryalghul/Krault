"""Modern custom widgets for Kristen Guard."""
import logging
import tkinter as tk
from tkinter import ttk
from typing import Callable, Optional


class ModernButton:
    """ Flat button with hover/press state drawn on a Canvas """

    def __init__(self, parent, text: str, command: Callable,
                 width: int = 140, height: int = 38,
                 style_config: Optional[dict] = None,
                 variant: str = "primary"):
        cfg = style_config or {}
        self.text    = text
        self.command = command
        self.width   = width
        self.height  = height
        self.cfg     = cfg
        self.variant = variant

        if variant == "secondary":
            self._bg    = cfg.get("secondary_bg_color", "#1a1a2e")
            self._hover = cfg.get("card_bg_color",      "#16213e")
            self._fg    = cfg.get("accent_color",       "#7b68ee")
        elif variant == "danger":
            self._bg    = cfg.get("error_color",        "#f85149")
            self._hover = self._adjust(self._bg, 20)
            self._fg    = "#ffffff"
        else:  # primary
            self._bg    = cfg.get("btn_bg_color",   "#452bd6")
            self._hover = cfg.get("btn_hover_color","#5a3de8")
            self._fg    = cfg.get("btn_fg_color",   "#ffffff")

        self._pressed  = False
        self._hovered  = False

        parent_bg = cfg.get("bg_color", "#0f0f23")
        self.canvas = tk.Canvas(
            parent, width=width, height=height,
            highlightthickness=0, relief="flat", bg=parent_bg)

        self._draw()
        self.canvas.bind("<Enter>",          self._enter)
        self.canvas.bind("<Leave>",          self._leave)
        self.canvas.bind("<Button-1>",       self._press)
        self.canvas.bind("<ButtonRelease-1>",self._release)

    def _adjust(self, color: str, pct: int) -> str:
        try:
            c = color.lstrip("#")
            r,g,b = int(c[0:2],16), int(c[2:4],16), int(c[4:6],16)
            r = min(255, r + int((255-r)*pct/100))
            g = min(255, g + int((255-g)*pct/100))
            b = min(255, b + int((255-b)*pct/100))
            return f"#{r:02x}{g:02x}{b:02x}"
        except Exception:
            return color

    def _draw(self) -> None:
        self.canvas.delete("all")
        bg = self._hover if self._hovered else self._bg
        if self._pressed:
            bg = self._adjust(bg, -15)

        r = self.cfg.get("border_radius", 10)
        w, h = self.width, self.height

        # Rounded rectangle via polygon with smooth=True
        pts = [r,0, w-r,0, w,0, w,r, w,h-r, w,h, w-r,h, r,h, 0,h, 0,h-r, 0,r, 0,0]
        self.canvas.create_polygon(pts, smooth=True, fill=bg, outline="")

        # Subtle border
        bdr = self.cfg.get("border_color", "#2d2d5a")
        self.canvas.create_polygon(pts, smooth=True, fill="", outline=bdr, width=1)

        self.canvas.create_text(
            w//2, h//2,
            text=self.text, fill=self._fg,
            font=self.cfg.get("button_font", ("Segoe UI", 11, "bold")))

    def _enter(self, _):    self._hovered = True;  self._draw()
    def _leave(self, _):    self._hovered = False; self._pressed = False; self._draw()
    def _press(self, _):    self._pressed = True;  self._draw()
    def _release(self, _):
        if self._pressed:
            self._pressed = False; self._draw()
            try: self.command()
            except Exception as e: logging.error(f"Button '{self.text}' error: {e}")

    def pack(self, **kw):  self.canvas.pack(**kw)
    def grid(self, **kw):  self.canvas.grid(**kw)
    def place(self, **kw): self.canvas.place(**kw)

    def configure(self, **kw):
        if "text"    in kw: self.text    = kw["text"]
        if "command" in kw: self.command = kw["command"]
        if "state"   in kw:
            # Dim the button visually when disabled
            self._fg = self.cfg.get("disabled_color","#4a4a6a") \
                       if kw["state"] == "disabled" \
                       else self.cfg.get("btn_fg_color","#ffffff")
        self._draw()


class CardFrame:

    def __init__(self, parent, style_config: dict, padding: int = 16):
        cfg = style_config
        self.frame = tk.Frame(
            parent,
            bg=cfg.get("card_bg_color", "#16213e"),
            relief="flat", bd=0,
            highlightbackground=cfg.get("border_color", "#2d2d5a"),
            highlightthickness=1)

    def get_inner_frame(self) -> tk.Frame:
        return self.frame

    def pack(self, **kw):  self.frame.pack(**kw)
    def grid(self, **kw):  self.frame.grid(**kw)
    def place(self, **kw): self.frame.place(**kw)


class ModernEntry:

    def __init__(self, parent, placeholder: str, style_config: dict,
                 width: int = 28, secret: bool = False):
        cfg = style_config
        self._placeholder = placeholder
        self._secret      = secret
        self._has_text    = False

        self.frame = tk.Frame(parent, bg=cfg.get("bg_color","#0f0f23"))

        self.entry = tk.Entry(
            self.frame,
            width=width,
            font=cfg.get("body_font", ("Segoe UI", 11)),
            bg=cfg.get("input_bg_color", cfg.get("secondary_bg_color","#1a1a2e")),
            fg=cfg.get("muted_fg_color", "#8888b8"),
            relief="flat",
            bd=0,
            highlightbackground=cfg.get("border_color","#2d2d5a"),
            highlightcolor=cfg.get("accent_color","#7b68ee"),
            highlightthickness=1,
            insertbackground=cfg.get("fg_color","#e8e8ff"),
            selectbackground=cfg.get("accent_color","#7b68ee"),
            selectforeground=cfg.get("bg_color","#0f0f23"))

        self.entry.insert(0, placeholder)
        self.entry.bind("<FocusIn>",  self._focus_in)
        self.entry.bind("<FocusOut>", self._focus_out)
        self.entry.pack(ipady=5, fill="x")

        self._cfg = cfg

    def _focus_in(self, _):
        if not self._has_text:
            self.entry.delete(0, tk.END)
            self.entry.config(fg=self._cfg.get("fg_color","#e8e8ff"))
            if self._secret:
                self.entry.config(show="●")
        self.entry.config(highlightcolor=self._cfg.get("accent_color","#7b68ee"))

    def _focus_out(self, _):
        if not self.entry.get():
            self._has_text = False
            self.entry.config(show="", fg=self._cfg.get("muted_fg_color","#8888b8"))
            self.entry.insert(0, self._placeholder)
        else:
            self._has_text = True
        self.entry.config(highlightbackground=self._cfg.get("border_color","#2d2d5a"))

    def get(self) -> str:
        v = self.entry.get()
        return "" if v == self._placeholder else v

    def set(self, value: str) -> None:
        self.entry.delete(0, tk.END)
        self.entry.insert(0, value)
        self._has_text = bool(value)
        self.entry.config(
            fg=self._cfg.get("fg_color","#e8e8ff") if value
            else self._cfg.get("muted_fg_color","#8888b8"),
            show="●" if (self._secret and value) else "")

    def clear(self) -> None:
        self.set("")

    def pack(self, **kw):  self.frame.pack(**kw)
    def grid(self, **kw):  self.frame.grid(**kw)
    def place(self, **kw): self.frame.place(**kw)


class StrengthBar:
    """ Five-dot password strength indicator. Scores 0–5. Each dot fills with the appropriate semantic colour """

    _COLORS = {
        0: "#444",
        1: "#f85149",   # critical
        2: "#d29922",   # weak
        3: "#d29922",   # fair
        4: "#3fb950",   # good
        5: "#58a6ff",   # strong
    }

    def __init__(self, parent, style_config: dict):
        cfg = style_config
        self.frame = tk.Frame(parent, bg=cfg.get("bg_color","#0f0f23"))
        self._dots = []
        self._empty = cfg.get("border_color","#2d2d5a")
        for _ in range(5):
            dot = tk.Label(self.frame, text="●", font=("Segoe UI",10),
                           bg=cfg.get("bg_color","#0f0f23"),
                           fg=self._empty)
            dot.pack(side="left", padx=1)
            self._dots.append(dot)

    def set_score(self, score: int) -> None:
        color = self._COLORS.get(max(0, min(5, score)), self._empty)
        for i, dot in enumerate(self._dots):
            dot.config(fg=color if i < score else self._empty)

    def pack(self, **kw):  self.frame.pack(**kw)
    def grid(self, **kw):  self.frame.grid(**kw)