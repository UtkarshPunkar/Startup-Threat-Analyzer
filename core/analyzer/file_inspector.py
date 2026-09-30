"""
Forensic File Inspector: Hashing, Shannon Entropy, PE Header Extraction & Anomaly Detection.
Optimized for high-speed batch static analysis and memory caching.
"""

import os
import math
import hashlib
import datetime
from typing import List, Dict, Any, Tuple, Optional
from core.models import PEFileInfo, PESectionInfo

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


class FileInspector:
    """Performs deep static inspection and cryptographic analysis on target binaries."""

    SUSPICIOUS_PACKER_SECTIONS = [
        '.upx0', '.upx1', '.upx2', '.vmp0', '.vmp1', '.themida', 
        '.aspack', '.adata', '.nsp0', '.nsp1', '.packer', '.petite', 
        '.pebundle', '.mpress1', '.mpress2', '.enigma1', '.enigma2'
    ]

    SUSPICIOUS_IMPORTS = [
        'virtualallocex', 'writeprocessmemory', 'createremotethread',
        'setwindowshookex', 'queueuserapc', 'ntunmapviewofsection',
        'isdebuggerpresent', 'checkremotedebuggerpresent', 'internetopenurl',
        'urlcache', 'cryptdecrypt', 'adjusttokenprivileges', 'samconnect'
    ]

    _cache: Dict[str, PEFileInfo] = {}

    @classmethod
    def calculate_entropy(cls, data: bytes) -> float:
        """Calculates the Shannon entropy of a byte array (0.0 to 8.0)."""
        if not data:
            return 0.0
        
        entropy = 0.0
        length = len(data)
        byte_counts = [0] * 256
        
        for b in data:
            byte_counts[b] += 1
            
        for count in byte_counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
                
        return round(entropy, 4)

    @classmethod
    def calculate_hashes(cls, filepath: str) -> Tuple[str, str, str]:
        """Calculates MD5, SHA-1, and SHA-256 for a given file."""
        md5_hash = hashlib.md5()
        sha1_hash = hashlib.sha1()
        sha256_hash = hashlib.sha256()
        
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    md5_hash.update(chunk)
                    sha1_hash.update(chunk)
                    sha256_hash.update(chunk)
            return md5_hash.hexdigest(), sha1_hash.hexdigest(), sha256_hash.hexdigest()
        except Exception:
            return "", "", ""

    @classmethod
    def inspect_file(cls, filepath: Optional[str]) -> PEFileInfo:
        """Inspects an executable binary, extracting hashes, entropy, and PE headers."""
        if not filepath or not os.path.isfile(filepath):
            info = PEFileInfo()
            info.file_path = filepath or ""
            info.exists = False
            return info

        norm_path = os.path.normpath(filepath).lower()
        try:
            mtime = os.path.getmtime(filepath)
            cache_key = f"{norm_path}::{mtime}"
            if cache_key in cls._cache:
                return cls._cache[cache_key]
        except Exception:
            cache_key = norm_path

        info = PEFileInfo()
        info.file_path = os.path.normpath(filepath)
        info.exists = True
        
        try:
            info.file_size = os.path.getsize(filepath)
            
            # Read first 512KB for fast entropy calculation and PE header check
            with open(filepath, 'rb') as f:
                data_sample = f.read(524288)
                
            info.entropy = cls.calculate_entropy(data_sample)
            info.is_high_entropy = info.entropy > 7.2
            
            md5_str, sha1_str, sha256_str = cls.calculate_hashes(filepath)
            info.md5 = md5_str
            info.sha1 = sha1_str
            info.sha256 = sha256_str

            # Parse PE headers if file is an executable (starts with 'MZ')
            if data_sample.startswith(b'MZ'):
                cls._parse_pe_structure(filepath, info)
                
        except Exception as e:
            info.anomalies.append(f"Inspection notice: {str(e)}")

        cls._cache[cache_key] = info
        return info

    @classmethod
    def _parse_pe_structure(cls, filepath: str, info: PEFileInfo):
        """Extracts PE headers, compilation timestamp, sections, and version metadata."""
        if PEFILE_AVAILABLE:
            try:
                pe = pefile.PE(filepath, fast_load=True)
                
                # Compilation timestamp
                if hasattr(pe, 'FILE_HEADER') and hasattr(pe.FILE_HEADER, 'TimeDateStamp'):
                    ts = pe.FILE_HEADER.TimeDateStamp
                    try:
                        compile_dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
                        info.compile_time = compile_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                        
                        now = datetime.datetime.now(datetime.timezone.utc)
                        if compile_dt > now + datetime.timedelta(days=1):
                            info.anomalies.append(f"Timestomping anomaly: Compile timestamp is in the future ({info.compile_time})")
                        elif compile_dt.year < 1995:
                            info.anomalies.append(f"Timestomping anomaly: Ancient compile timestamp ({info.compile_time})")
                    except Exception:
                        info.compile_time = str(ts)

                # Subsystem
                if hasattr(pe, 'OPTIONAL_HEADER') and hasattr(pe.OPTIONAL_HEADER, 'Subsystem'):
                    subsystem_map = {1: "Native/Driver", 2: "Windows GUI", 3: "Windows Console", 7: "POSIX", 9: "Windows CE"}
                    info.subsystem = subsystem_map.get(pe.OPTIONAL_HEADER.Subsystem, f"Other ({pe.OPTIONAL_HEADER.Subsystem})")

                # Section Analysis
                for section in pe.sections[:6]:
                    sec_name = section.Name.decode('utf-8', errors='ignore').strip('\x00').strip()
                    
                    sec_info = {
                        "name": sec_name,
                        "virtual_size": section.Misc_VirtualSize,
                        "raw_size": section.SizeOfRawData,
                        "entropy": 0.0
                    }
                    info.sections.append(sec_info)

                    # Check packer section names
                    if any(p in sec_name.lower() for p in cls.SUSPICIOUS_PACKER_SECTIONS):
                        info.anomalies.append(f"Known packer/crypter section identified: '{sec_name}'")

                # Parse Directory Entries if available
                pe.parse_data_directories(directories=[
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']
                ])

                # Imphash
                try:
                    info.imphash = pe.get_imphash()
                except Exception:
                    pass

                # Imports Analysis
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    found_suspicious_imports = []
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        for imp in entry.imports:
                            if imp and imp.name:
                                imp_name = imp.name.decode('utf-8', errors='ignore').lower()
                                if any(s in imp_name for s in cls.SUSPICIOUS_IMPORTS):
                                    found_suspicious_imports.append(imp.name.decode('utf-8', errors='ignore'))
                    if found_suspicious_imports:
                        info.imports_sample = found_suspicious_imports[:6]
                        info.anomalies.append(f"Suspicious API imports detected: {', '.join(found_suspicious_imports[:4])}")

                # Version Information
                if hasattr(pe, 'FileInfo'):
                    for fi in pe.FileInfo:
                        for item in fi:
                            if hasattr(item, 'StringTable'):
                                for st in item.StringTable:
                                    for key, val in st.entries.items():
                                        k_str = key.decode('utf-8', errors='ignore').lower()
                                        v_str = val.decode('utf-8', errors='ignore')
                                        if 'companyname' in k_str:
                                            info.company_name = v_str
                                        elif 'filedescription' in k_str:
                                            info.file_description = v_str
                                        elif 'productname' in k_str:
                                            info.product_name = v_str
                                        elif 'originalfilename' in k_str:
                                            info.original_filename = v_str
                pe.close()
            except Exception:
                pass
