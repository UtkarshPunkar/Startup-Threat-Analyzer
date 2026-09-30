"""
Base class and common path/string utilities for ASEP collectors.
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Tuple
import os
import re
import shlex
from core.models import StartupEntry, ASEPCategory


class BaseCollector(ABC):
    """Abstract base class for all startup persistence collectors."""

    @abstractmethod
    def collect(self) -> List[StartupEntry]:
        """Collect and return all startup/persistence entries for this vector."""
        pass

    @staticmethod
    def normalize_path(raw_path: str) -> Optional[str]:
        """
        Expands environment variables, strips quotes, and normalizes file paths.
        """
        if not raw_path or not isinstance(raw_path, str):
            return None
        
        cleaned = raw_path.strip().strip('"').strip("'")
        if not cleaned:
            return None
            
        try:
            expanded = os.path.expandvars(cleaned)
            # Expand system-specific variables if not already expanded
            if "%SystemRoot%" in expanded or "%systemroot%" in expanded:
                expanded = re.sub(r'(?i)%systemroot%', os.environ.get('SystemRoot', r'C:\Windows'), expanded)
            if "%windir%" in expanded or "%WinDir%" in expanded:
                expanded = re.sub(r'(?i)%windir%', os.environ.get('WINDIR', r'C:\Windows'), expanded)
            if "%ProgramFiles%" in expanded:
                expanded = re.sub(r'(?i)%programfiles%', os.environ.get('ProgramFiles', r'C:\Program Files'), expanded)
            if "%ProgramData%" in expanded:
                expanded = re.sub(r'(?i)%programdata%', os.environ.get('ProgramData', r'C:\ProgramData'), expanded)
            if "%APPDATA%" in expanded:
                expanded = re.sub(r'(?i)%appdata%', os.environ.get('APPDATA', ''), expanded)
            if "%LOCALAPPDATA%" in expanded:
                expanded = re.sub(r'(?i)%localappdata%', os.environ.get('LOCALAPPDATA', ''), expanded)
            if "%TEMP%" in expanded or "%TMP%" in expanded:
                expanded = re.sub(r'(?i)%(temp|tmp)%', os.environ.get('TEMP', ''), expanded)
                
            norm = os.path.normpath(expanded)
            return norm
        except Exception:
            return cleaned

    @classmethod
    def parse_command_line(cls, raw_command: str) -> Tuple[Optional[str], str]:
        """
        Parses a full command line string into (resolved_binary_path, arguments).
        Handles quoted paths with spaces, unquoted paths, system32 lookups, and LOLBins.
        """
        if not raw_command or not isinstance(raw_command, str):
            return None, ""

        cmd = raw_command.strip()
        if not cmd:
            return None, ""

        # Case 1: Quoted executable (e.g., "C:\Program Files\App\app.exe" --arg1)
        if cmd.startswith('"'):
            end_quote = cmd.find('"', 1)
            if end_quote != -1:
                exe_part = cmd[1:end_quote]
                args_part = cmd[end_quote + 1:].strip()
                return cls.normalize_path(exe_part), args_part

        # Case 2: Standard whitespace split or checking existing files on disk
        parts = cmd.split()
        if not parts:
            return None, ""

        # Check progressively if concatenated path exists on disk (handles unquoted paths with spaces)
        accumulated = ""
        for i, part in enumerate(parts):
            accumulated = f"{accumulated} {part}".strip() if accumulated else part
            expanded_acc = cls.normalize_path(accumulated)
            if expanded_acc and os.path.isfile(expanded_acc):
                args = " ".join(parts[i + 1:])
                return expanded_acc, args

        # Case 3: First token is binary name or path
        first_token = parts[0]
        args = " ".join(parts[1:])
        norm_first = cls.normalize_path(first_token)

        # If it doesn't have an extension, try checking with .exe
        if norm_first and not os.path.splitext(norm_first)[1]:
            if os.path.isfile(norm_first + ".exe"):
                return norm_first + ".exe", args

        # If it is a bare executable (e.g. `notepad.exe` or `powershell.exe`), check in System32 / Path
        if norm_first and not os.path.isabs(norm_first):
            system32 = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32')
            candidate = os.path.join(system32, norm_first)
            if os.path.isfile(candidate):
                return candidate, args
            if os.path.isfile(candidate + ".exe"):
                return candidate + ".exe", args

        return norm_first, args
