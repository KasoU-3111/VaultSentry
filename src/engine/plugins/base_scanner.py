"""
VaultSentry - Base Scanner Abstract Contract
Enforces uniform execution interface across all static analysis engine plugins.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Any


class BaseScanner(ABC):
    """
    Abstract Base Class for all VaultSentry scanner plugins.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier name for the scanner plugin."""
        pass

    @abstractmethod
    def scan(self, file_path: Path) -> Dict[str, Any]:
        """
        Executes static analysis on the target file.
        
        :param file_path: Resolved path to target file in VQS.
        :return: Standardized scanner result dictionary.
        """
        pass