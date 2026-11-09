"""AgentGuard: OS-level zero-trust security kernel and background daemon."""

__version__ = "0.1.0"
__author__ = "AgentGuard Authors"
__license__ = "Apache-2.0"

__all__ = [
    "__version__",
    "__author__",
    "__license__",
    "AgentProfile",
    "load_profile",
    "list_available_profiles",
]

try:
    from agentguard.config import (  # noqa: F401
        AgentProfile,
        list_available_profiles,
        load_profile,
    )
except ImportError:
    pass
