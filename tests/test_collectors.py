"""
Unit tests for ASEP collectors and path utilities.
"""

import os
import pytest
from core.collectors.base import BaseCollector
from core.collectors.registry_collector import RegistryCollector
from core.collectors.folder_collector import FolderCollector
from core.models import StartupEntry, ASEPCategory


def test_path_normalization():
    norm = BaseCollector.normalize_path(r'"%SystemRoot%\System32\cmd.exe"')
    assert norm is not None
    assert "System32" in norm
    assert not norm.startswith('"')
    assert not norm.endswith('"')


def test_command_line_parsing_quoted():
    cmd = r'"C:\Program Files\Vendor App\app.exe" --silent --port 8080'
    resolved, args = BaseCollector.parse_command_line(cmd)
    assert resolved == r"C:\Program Files\Vendor App\app.exe"
    assert args == "--silent --port 8080"


def test_command_line_parsing_unquoted():
    cmd = r"powershell.exe -ExecutionPolicy Bypass -File test.ps1"
    resolved, args = BaseCollector.parse_command_line(cmd)
    assert resolved is not None
    assert "powershell" in resolved.lower()
    assert "-ExecutionPolicy Bypass" in args


def test_folder_collector():
    collector = FolderCollector()
    entries = collector.collect()
    assert isinstance(entries, list)
    for e in entries:
        assert isinstance(e, StartupEntry)
        assert e.category == ASEPCategory.STARTUP_FOLDER
