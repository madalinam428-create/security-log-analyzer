"""Security Log Analyzer package."""

from .analyzer import analyze_events
from .parser import parse_file, parse_line, parse_lines

__all__ = ["analyze_events", "parse_file", "parse_line", "parse_lines"]
__version__ = "1.0.0"

