"""Mephisto - WordPress vulnerability scanner and exploitation framework."""

from .config import VERSION
from .client import Exploit
from .registry import ExploitSpec, discover, load_function

__version__ = VERSION

__all__ = ["Exploit", "ExploitSpec", "discover", "load_function", "__version__"]
