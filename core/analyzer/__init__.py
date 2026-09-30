"""
Analyzer package for file inspection, Authenticode signature verification, heuristics, and MITRE mapping.
"""

from core.analyzer.file_inspector import FileInspector
from core.analyzer.signature_verifier import SignatureVerifier
from core.analyzer.heuristics import HeuristicAnalyzer
from core.analyzer.mitre_mapper import MITREMapper

__all__ = [
    "FileInspector",
    "SignatureVerifier",
    "HeuristicAnalyzer",
    "MITREMapper"
]
