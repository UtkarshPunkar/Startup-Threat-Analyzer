"""
Collectors package for Auto-Start Extensibility Points (ASEP).
"""

from core.collectors.base import BaseCollector
from core.collectors.registry_collector import RegistryCollector
from core.collectors.folder_collector import FolderCollector
from core.collectors.task_collector import TaskCollector
from core.collectors.service_collector import ServiceCollector
from core.collectors.wmi_collector import WMICollector
from core.collectors.driver_collector import DriverCollector

__all__ = [
    "BaseCollector",
    "RegistryCollector",
    "FolderCollector",
    "TaskCollector",
    "ServiceCollector",
    "WMICollector",
    "DriverCollector",
]
