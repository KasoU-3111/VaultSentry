"""
VaultSentry - Base Scanner Abstract Contract
Enforces uniform execution interface across all static analysis engine plugins.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, Optional


class BaseScanner(ABC):
    """
    Abstract Base Class for all VaultSentry static security analysis plugins.
    Implements Liskov Substitution Principle to allow flexible engine expansion.
    """

    @property
    @abstractmethod
    def scanner_id(self) -> str:
        """Unique string identifier for the scanner module (e.g., 'IdentityScanner')."""
        pass

    @property
    def priority(self) -> int:
        """
        Execution priority order (Lower values execute earlier).
        Default: 50. Identity/Integrity scanners run at priority 10.
        """
        return 50

    def is_applicable(self, file_path: Path, context: Optional[Dict[str, Any]] = None) -> bool:
        """
        Determines whether this scanner should run against the target file.
        Override in sub-classes to filter by file extensions or magic byte headers.
        """
        return True

    @abstractmethod
    def scan(self, file_path: Path, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Executes static analysis on the target file within Virtual Quarantine Space (VQS).

        :param file_path: Resolved path to target file in VQS.
        :param context: Shared pipeline execution context dictionary.
        :return: Standardized scanner result dictionary.
        """
        pass