"""
Collector for Windows Scheduled Tasks (Boot, Logon, and Suspicious Persistent Triggers).
"""

import os
import csv
import io
import subprocess
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional
from core.models import StartupEntry, ASEPCategory
from core.collectors.base import BaseCollector


class TaskCollector(BaseCollector):
    """Enumerates Windows Scheduled Tasks with startup, logon, or high-privilege triggers."""

    def collect(self) -> List[StartupEntry]:
        # Try schtasks CSV parser first (fast & comprehensive)
        entries = self._collect_schtasks_csv()
        if entries:
            return entries

        # Fallback to direct XML parsing in C:\Windows\System32\Tasks
        return self._collect_tasks_filesystem()

    def _collect_schtasks_csv(self) -> List[StartupEntry]:
        results: List[StartupEntry] = []
        try:
            cmd = ['schtasks.exe', '/Query', '/FO', 'CSV', '/V']
            proc = subprocess.run(cmd, capture_output=True, text=True, errors='ignore', timeout=15)
            if proc.returncode != 0 or not proc.stdout:
                return []

            reader = csv.DictReader(io.StringIO(proc.stdout))
            for row in reader:
                task_name = row.get("TaskName", "")
                if not task_name:
                    continue

                # Exclude internal benign Windows Defender or update tasks if clean, but keep in scope for inspection
                task_to_run = row.get("Task To Run", "") or row.get("Action", "")
                if not task_to_run or task_to_run.lower() == "n/a" or task_to_run.lower() == "com handler":
                    continue

                status = row.get("Status", "Ready")
                author = row.get("Author", "")
                user_context = row.get("Run As User", "SYSTEM") or "SYSTEM"
                schedule_type = row.get("Schedule Type", "") or row.get("Triggers", "")
                
                # Check if it triggers at logon, boot, or periodic
                is_startup_trigger = any(kw in schedule_type.lower() for kw in ["logon", "boot", "startup", "idle", "at system start"])

                resolved_path, args = self.parse_command_line(task_to_run)
                enabled = "disabled" not in status.lower()

                # Clean remediation command
                esc_task = task_name.strip('"')
                rem_cmd = f'Unregister-ScheduledTask -TaskName "{esc_task}" -Confirm:$false -ErrorAction SilentlyContinue'

                entry = StartupEntry(
                    name=f"Task: {os.path.basename(task_name)}",
                    category=ASEPCategory.SCHEDULED_TASK,
                    location=f"Task Scheduler: {task_name}",
                    raw_command=task_to_run,
                    resolved_path=resolved_path,
                    arguments=args,
                    enabled=enabled,
                    user_context=f"{user_context} ({schedule_type})",
                    remediation_command=rem_cmd
                )
                results.append(entry)

        except Exception:
            pass
            
        return results

    def _collect_tasks_filesystem(self) -> List[StartupEntry]:
        """Fallback method: parses raw Task XML files in C:\\Windows\\System32\\Tasks."""
        results: List[StartupEntry] = []
        tasks_dir = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), r"System32\Tasks")
        if not os.path.isdir(tasks_dir):
            return []

        for root, _, files in os.walk(tasks_dir):
            for file in files:
                filepath = os.path.join(root, file)
                rel_name = os.path.relpath(filepath, tasks_dir).replace('/', '\\')
                try:
                    with open(filepath, 'r', encoding='utf-16', errors='ignore') as f:
                        content = f.read()
                    if not content.strip():
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                    
                    root_elem = ET.fromstring(content)
                    ns = {'ns': root_elem.tag.split('}')[0].strip('{')} if '}' in root_elem.tag else {}
                    
                    # Extract Exec action
                    exec_elem = root_elem.find('.//ns:Exec', ns) if ns else root_elem.find('.//Exec')
                    if exec_elem is not None:
                        command_elem = exec_elem.find('ns:Command', ns) if ns else exec_elem.find('Command')
                        args_elem = exec_elem.find('ns:Arguments', ns) if ns else exec_elem.find('Arguments')
                        
                        cmd_str = command_elem.text if command_elem is not None and command_elem.text else ""
                        args_str = args_elem.text if args_elem is not None and args_elem.text else ""
                        
                        if cmd_str:
                            full_raw = f"{cmd_str} {args_str}".strip()
                            resolved = self.normalize_path(cmd_str)
                            rem_cmd = f'Unregister-ScheduledTask -TaskName "{rel_name}" -Confirm:$false -ErrorAction SilentlyContinue'
                            
                            entry = StartupEntry(
                                name=f"Task: {file}",
                                category=ASEPCategory.SCHEDULED_TASK,
                                location=f"Tasks\\{rel_name}",
                                raw_command=full_raw,
                                resolved_path=resolved,
                                arguments=args_str,
                                enabled=True,
                                user_context="SYSTEM",
                                remediation_command=rem_cmd
                            )
                            results.append(entry)
                except Exception:
                    continue

        return results
