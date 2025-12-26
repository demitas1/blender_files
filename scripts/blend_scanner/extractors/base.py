"""Base extractor class for data extraction from Blender."""

from abc import ABC, abstractmethod
from typing import Any


class BaseExtractor(ABC):
    """Abstract base class for Blender data extractors."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the extractor name."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Return a brief description of what this extractor extracts."""
        pass

    @abstractmethod
    def extract(self) -> Any:
        """
        Extract data from Blender.

        This method is intended to be called from within Blender's Python environment.
        It uses the bpy module to access Blender data.

        Returns:
            Extracted data (type depends on extractor)
        """
        pass

    @abstractmethod
    def format_output(self, data: Any) -> str:
        """
        Format extracted data as string output.

        Args:
            data: The extracted data

        Returns:
            Formatted string representation
        """
        pass
