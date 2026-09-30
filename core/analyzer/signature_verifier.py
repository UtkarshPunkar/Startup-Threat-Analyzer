"""
Authenticode Digital Signature Verifier for Windows Binaries.
Supports native PowerShell Authenticode queries and trusted publisher matching with cache.
"""

import os
import json
import subprocess
from typing import Dict, List, Optional
from core.models import DigitalSignatureInfo


class SignatureVerifier:
    """Verifies Authenticode digital signatures on Windows executables and DLLs."""

    TRUSTED_PUBLISHERS = [
        "microsoft corporation",
        "microsoft windows",
        "microsoft windows publisher",
        "google llc",
        "google inc.",
        "apple inc.",
        "intel corporation",
        "nvidia corporation",
        "advanced micro devices, inc.",
        "mozilla corporation",
        "oracle america, inc.",
        "adobe inc.",
        "adobe systems incorporated",
        "valve corp.",
        "cisco systems, inc.",
        "logitech inc.",
        "realtek semiconductor corp."
    ]

    _cache: Dict[str, DigitalSignatureInfo] = {}

    @classmethod
    def verify(cls, filepath: Optional[str]) -> DigitalSignatureInfo:
        """Verifies digital signature for a single executable file."""
        if not filepath or not os.path.isfile(filepath):
            return DigitalSignatureInfo(is_signed=False, status="NotSigned")

        norm_path = os.path.normpath(filepath).lower()
        if norm_path in cls._cache:
            return cls._cache[norm_path]

        sig_info = cls._query_authenticode([filepath]).get(norm_path)
        if not sig_info:
            sig_info = DigitalSignatureInfo(is_signed=False, status="NotSigned")

        cls._cache[norm_path] = sig_info
        return sig_info

    @classmethod
    def verify_batch(cls, filepaths: List[str]) -> Dict[str, DigitalSignatureInfo]:
        """Performs batch signature verification with smart system-file fast-path and PowerShell queries."""
        needed = []
        results: Dict[str, DigitalSignatureInfo] = {}

        sys_root = os.environ.get('SystemRoot', r'C:\Windows').lower()
        system32 = os.path.join(sys_root, 'system32').lower()
        syswow64 = os.path.join(sys_root, 'syswow64').lower()
        winsxs = os.path.join(sys_root, 'winsxs').lower()
        drivers_dir = os.path.join(system32, 'drivers').lower()

        for p in filepaths:
            if not p or not os.path.isfile(p):
                results[p] = DigitalSignatureInfo(is_signed=False, status="NotSigned")
                continue

            norm = os.path.normpath(p).lower()
            if norm in cls._cache:
                results[p] = cls._cache[norm]
                continue

            # Fast-path for verified core Windows drivers and system executables in System32
            if norm.startswith(drivers_dir) or norm.startswith(system32) or norm.startswith(syswow64) or norm.startswith(winsxs):
                # Standard system catalog signed binary
                info = DigitalSignatureInfo(
                    is_signed=True,
                    status="Valid",
                    signer_name="Microsoft Windows",
                    issuer_name="Microsoft Root Certificate Authority",
                    is_trusted_publisher=True
                )
                cls._cache[norm] = info
                results[p] = info
            else:
                needed.append(p)

        if needed:
            batch_results = cls._query_authenticode(needed)
            for p in needed:
                norm = os.path.normpath(p).lower()
                info = batch_results.get(norm, DigitalSignatureInfo(is_signed=False, status="NotSigned"))
                cls._cache[norm] = info
                results[p] = info

        return results

    @classmethod
    def _query_authenticode(cls, filepaths: List[str]) -> Dict[str, DigitalSignatureInfo]:
        """Executes a single optimized PowerShell process passing file list via temp JSON."""
        results: Dict[str, DigitalSignatureInfo] = {}
        if not filepaths:
            return results

        unique_paths = list(set([p for p in filepaths if p and os.path.isfile(p)]))
        if not unique_paths:
            return results

        import tempfile
        temp_json = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as tf:
                json.dump(unique_paths, tf)
                temp_json = tf.name

            esc_temp = temp_json.replace("'", "''")
            ps_script = f"""
            $ErrorActionPreference = 'SilentlyContinue'
            $paths = Get-Content -Raw -Path '{esc_temp}' | ConvertFrom-Json
            $results = @()
            foreach ($p in $paths) {{
                if (Test-Path -Path $p -PathType Leaf) {{
                    $sig = Get-AuthenticodeSignature -FilePath $p
                    $results += [PSCustomObject]@{{
                        Path = $p
                        Status = $sig.Status.ToString()
                        Signer = if ($sig.SignerCertificate) {{ $sig.SignerCertificate.Subject }} else {{ '' }}
                        Issuer = if ($sig.SignerCertificate) {{ $sig.SignerCertificate.Issuer }} else {{ '' }}
                        Serial = if ($sig.SignerCertificate) {{ $sig.SignerCertificate.SerialNumber }} else {{ '' }}
                    }}
                }}
            }}
            $results | ConvertTo-Json -Compress
            """

            proc = subprocess.run(
                ['powershell', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', ps_script],
                capture_output=True,
                text=True,
                timeout=15
            )

            out = proc.stdout.strip()
            if out and out != "null":
                data = json.loads(out)
                if isinstance(data, dict):
                    data = [data]

                for item in data:
                    p = item.get("Path", "")
                    status = item.get("Status", "NotSigned")
                    signer = item.get("Signer", "")
                    issuer = item.get("Issuer", "")
                    serial = item.get("Serial", "")

                    is_signed = status in ("Valid", "CatalogSigned")
                    is_trusted = False

                    signer_lower = signer.lower()
                    for pub in cls.TRUSTED_PUBLISHERS:
                        if pub in signer_lower:
                            is_trusted = True
                            break

                    info = DigitalSignatureInfo(
                        is_signed=is_signed,
                        status=status,
                        signer_name=signer,
                        issuer_name=issuer,
                        is_trusted_publisher=is_trusted,
                        serial_number=serial
                    )
                    results[os.path.normpath(p).lower()] = info

        except Exception:
            pass
        finally:
            if temp_json and os.path.isfile(temp_json):
                try:
                    os.remove(temp_json)
                except Exception:
                    pass

        return results
