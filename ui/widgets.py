"""Custom UI widgets and components"""
import tkinter as tk
from tkinter import ttk
import logging
from typing import Callable, Tuple, Optional, Any

from config.themes import get_style_config

class RoundedButton(tk.Canvas):
    def __init__(self, parent, text: str, command: Callable, 
                 bg_color: str = '#4CAF50', 
                 fg_color: str = "#ffffff",
                 hover_color: str = '#45a049',
                 active_color: str = '#3d8b40',
                 corner_radius: int = 20,
                 width: int = 120, 
                 height: int = 40,
                 font_family: str = 'Segoe UI',
                 font_size: int = 11,
                 font_weight: str = 'normal',
                 padding: Tuple[int, int] = (20, 10),
                 **kwargs):
        """ Initialize a custom rounded button """
        # Handle different parent types - ttk.Frame doesn't have 'background' option
        try:
            parent_bg = parent.cget('background') if hasattr(parent, 'cget') else '#1e1e1e'
        except Exception:
            # Fallback
            parent_bg = '#1e1e1e'
        
        # Initialize Canvas widget with transparent background
        super().__init__(parent, 
                        width=width, 
                        height=height, 
                        highlightthickness=0,  # Remove focus border
                        background=parent_bg,
                        **kwargs)
        
        # Store button properties for state management
        self.command = command
        self.text = text
        self.bg_color = bg_color
        self.fg_color = fg_color
        self.hover_color = hover_color
        self.active_color = active_color
        self.corner_radius = corner_radius
        self.width = width
        self.height = height
        self.font = (font_family, font_size, font_weight)
        self.padding = padding
        
        # State tracking variables
        self.is_hovered = False  # Mouse is over button
        self.is_pressed = False  # Mouse button is pressed
        self.is_enabled = True   # Button is active/clickable
        
        # Canvas element references
        self.button_bg = None   # Rounded rectangle background
        self.button_text = None # Text element
        
        # Set up event bindings for interactivity
        self._setup_bindings()
        
        # Initial render of the button
        self.draw_button()
    
    def _setup_bindings(self) -> None:
        """ et up mouse and keyboard event bindings for button interactions """
        # Mouse enter/leave for hover effects
        self.bind("<Enter>", self._on_enter, add='+')
        self.bind("<Leave>", self._on_leave, add='+')
        
        # Mouse press/release for click effects
        self.bind("<Button-1>", self._on_press, add='+')
        self.bind("<ButtonRelease-1>", self._on_release, add='+')
        
        # Keyboard support
        self.bind("<FocusIn>", self._on_focus, add='+')
        self.bind("<FocusOut>", self._on_blur, add='+')
        self.bind("<Return>", self._on_keypress, add='+')
        self.bind("<space>", self._on_keypress, add='+')
        
        # Make button focusable for keyboard navigation
        self.configure(takefocus=1)
        
    def draw_button(self) -> None:
        """ Draw the rounded button with current state (normal/hover/pressed/disabled) """
        try:
            # Clear all previous canvas elements
            self.delete("all")
            
            # Determine current state color based on button state
            if not self.is_enabled:
                current_color = self._adjust_brightness(self.bg_color, -30)  # Dimmed for disabled
            elif self.is_pressed:
                current_color = self.active_color  # Pressed state
            elif self.is_hovered:
                current_color = self.hover_color   # Hover state
            else:
                current_color = self.bg_color      # Normal state
            
            # Draw rounded rectangle background with outline
            self.button_bg = self.create_rounded_rectangle(
                2, 2, self.width-2, self.height-2,  # Slightly inset for border
                radius=self.corner_radius,
                fill=current_color,  # Main fill color
                outline=self._adjust_brightness(current_color, -20),  # Darker outline
                width=1  # Outline width
            )
            
            # Draw button text centered in the button
            self.button_text = self.create_text(
                self.width // 2, # Center horizontally
                self.height // 2, # Center vertically
                text=self.text,
                fill=self.fg_color, # Text color
                font=self.font, # Text font
                state="normal" if self.is_enabled else "disabled" # Text state
            )
            
        except Exception as e:
            logging.error(f"Error drawing rounded button '{self.text}': {e}")
            self.delete("all")
            self.create_rectangle(2, 2, self.width-2, self.height-2, 
                                fill=self.bg_color, outline=self.fg_color)
            self.create_text(self.width//2, self.height//2, text=self.text, 
                           fill=self.fg_color, font=self.font)
    
    def create_rounded_rectangle(self, x1: int, y1: int, x2: int, y2: int, 
                               radius: int = 25, **kwargs) -> int:
        points = []
        
        # Top side (left to right)
        points.extend([x1 + radius, y1])
        points.extend([x2 - radius, y1])
        
        # Top-right corner
        points.extend([x2, y1])
        points.extend([x2, y1 + radius])
        
        # Right side (top to bottom)
        points.extend([x2, y2 - radius])
        
        # Bottom-right corner
        points.extend([x2, y2])
        points.extend([x2 - radius, y2])
        
        # Bottom side (right to left)
        points.extend([x1 + radius, y2])
        
        # Bottom-left corner
        points.extend([x1, y2])
        points.extend([x1, y2 - radius])
        
        # Left side (bottom to top)
        points.extend([x1, y1 + radius])
        
        # Top-left corner
        points.extend([x1, y1])
        points.extend([x1 + radius, y1])
        
        # Create polygon for rounded effect
        return self.create_polygon(points, smooth=True, **kwargs)
    
    def _adjust_brightness(self, color: str, amount: int) -> str:
        """ Adjust color brightness by a specified amount """
        try:
            if not color.startswith('#'):
                return color
                
            # Convert hex to RGB components
            r = int(color[1:3], 16)
            g = int(color[3:5], 16)
            b = int(color[5:7], 16)
            
            # Adjust brightness with bounds checking
            r = max(0, min(255, r + amount))
            g = max(0, min(255, g + amount))
            b = max(0, min(255, b + amount))
            
            # Convert back to hex format
            return f"#{r:02x}{g:02x}{b:02x}"
            
        except (ValueError, IndexError) as e:
            logging.warning(f"Color adjustment failed for {color}: {e}")
            return color  # Return original color on error
    
    def _on_enter(self, event: tk.Event) -> None:
        if self.is_enabled:
            self.is_hovered = True
            self.draw_button()  # Redraw with hover color
    
    def _on_leave(self, event: tk.Event) -> None:
        if self.is_enabled:
            self.is_hovered = False
            self.is_pressed = False
            self.draw_button()  # Redraw with normal color
    
    def _on_press(self, event: tk.Event) -> None:
        if self.is_enabled:
            self.is_pressed = True
            self.draw_button()  # Redraw with pressed color
            # Return focus to button for keyboard accessibility
            self.focus_set()
    
    def _on_release(self, event: tk.Event) -> None:
        if self.is_enabled and self.is_pressed:
            self.is_pressed = False
            self.draw_button()  # Redraw with appropriate color
            
            # Check if release is within button bounds (not dragged outside)
            x, y = event.x, event.y
            if 0 <= x <= self.width and 0 <= y <= self.height:
                try:
                    if self.command and callable(self.command):
                        self.command()
                except Exception as e:
                    logging.error(f"Button command failed for '{self.text}': {e}")
    
    def _on_focus(self, event: tk.Event) -> None:
        if self.is_enabled:
            self.is_hovered = True
            self.draw_button()  # Redraw with focus/hover appearance
    
    def _on_blur(self, event: tk.Event) -> None:
        if self.is_enabled:
            self.is_hovered = False
            self.is_pressed = False
            self.draw_button()  # Redraw with normal appearance
    
    def _on_keypress(self, event: tk.Event) -> None:
        if self.is_enabled:
            self.is_pressed = True
            self.draw_button()  # Visual feedback
            self.after(150, self._execute_command)  # Brief delay for visual feedback
    
    def _execute_command(self) -> None:
        self.is_pressed = False
        self.draw_button()  # Reset appearance
        try:
            if self.command and callable(self.command):
                self.command()
        except Exception as e:
            logging.error(f"Button command failed for '{self.text}': {e}")
    
    def configure(self, **kwargs) -> None:
        """ Configure button properties dynamically """
        if 'text' in kwargs:
            self.text = kwargs['text']
            
        if 'bg_color' in kwargs:
            self.bg_color = kwargs['bg_color']
            
        if 'state' in kwargs:
            state = kwargs['state']
            if state in ['normal', 'active']:
                self.is_enabled = True
            elif state in ['disabled', 'inactive']:
                self.is_enabled = False
            else:
                logging.warning(f"Unknown button state: {state}")
                
        if 'command' in kwargs:
            self.command = kwargs['command']
            
        # Redraw with new configuration
        self.draw_button()
    
    def grid(self, **kwargs) -> None:
        """ Custom grid geometry manager implementation for RoundedButton """
        filtered_kwargs = kwargs.copy()
        
        if 'sticky' in filtered_kwargs:
            logging.debug(f"Removing unsupported 'sticky' option from RoundedButton grid configuration")
            filtered_kwargs.pop('sticky')
            
        unsupported_options = ['ipadx', 'ipady']
        for option in unsupported_options:
            if option in filtered_kwargs:
                logging.debug(f"Removing unsupported '{option}' option from RoundedButton grid configuration")
                filtered_kwargs.pop(option)
        
        super().grid(**filtered_kwargs)
    
    def pack(self, **kwargs) -> None:
        super().pack(**kwargs)
    
    def place(self, **kwargs) -> None:

        super().place(**kwargs)
    
    def enable(self) -> None:
        """ Enable the button for interaction """
        self.is_enabled = True
        self.draw_button()
    
    def disable(self) -> None:
        """ Disable the button """
        self.is_enabled = False
        self.draw_button()