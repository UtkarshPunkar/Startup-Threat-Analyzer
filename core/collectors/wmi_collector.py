"""
Collector for WMI Event Subscriptions (Advanced APT Persistence).
Enumerates __EventFilter, CommandLineEventConsumer, and ActiveScriptEventConsumer in root\\subscription.
"""

import json
import subprocess
from typing import List
from core.models import StartupEntry, ASEPCategory
from core.collectors.base import BaseCollector


class WMICollector(BaseCollector):
    """Enumerates WMI Event Filter-to-Consumer Bindings."""

    def collect(self) -> List[StartupEntry]:
        results: List[StartupEntry] = []
        
        # Query WMI CommandLineEventConsumer and ActiveScriptEventConsumer via PowerShell
        ps_script = """
        $consumers = @()
        try {
            $cmdConsumers = Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue
            foreach ($c in $cmdConsumers) {
                $consumers += [PSCustomObject]@{
                    Type = "CommandLineEventConsumer"
                    Name = $c.Name
                    Command = $c.CommandLineTemplate
                    Executable = $c.ExecutablePath
                }
            }
        } catch {}

        try {
            $scriptConsumers = Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer -ErrorAction SilentlyContinue
            foreach ($s in $scriptConsumers) {
                $consumers += [PSCustomObject]@{
                    Type = "ActiveScriptEventConsumer"
                    Name = $s.Name
                    Command = if ($s.ScriptText) { $s.ScriptText.Substring(0, [Math]::Min(150, $s.ScriptText.Length)) } else { $s.ScriptFileName }
                    Executable = $s.ScriptFileName
                }
            }
        } catch {}

        $consumers | ConvertTo-Json -Compress
        """
        
        try:
            proc = subprocess.run(
                ['powershell', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', ps_script],
                capture_output=True,
                text=True,
                timeout=8
            )
            out = proc.stdout.strip()
            if out and out != "null":
                data = json.loads(out)
                if isinstance(data, dict):
                    data = [data]
                
                for item in data:
                    c_type = item.get("Type", "CommandLineEventConsumer")
                    name = item.get("Name", "WMI Consumer")
                    cmd = item.get("Command", "") or item.get("Executable", "")
                    exe_path = item.get("Executable", "") or cmd

                    resolved_path, args = self.parse_command_line(exe_path)
                    rem_cmd = f'Get-CimInstance -Namespace root/subscription -ClassName {c_type} -Filter "Name=\'{name}\'" | Remove-CimInstance'

                    entry = StartupEntry(
                        name=f"WMI Subscription: {name}",
                        category=ASEPCategory.WMI_SUBSCRIPTION,
                        location=f"root\\subscription\\{c_type} ({name})",
                        raw_command=cmd,
                        resolved_path=resolved_path,
                        arguments=args,
                        enabled=True,
                        user_context="NT AUTHORITY\\SYSTEM (WMI Provider)",
                        remediation_command=rem_cmd
                    )
                    results.append(entry)
        except Exception:
            pass

        return results
