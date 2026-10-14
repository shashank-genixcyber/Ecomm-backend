"""Initialize synthetic configuration before pytest-django loads app settings."""
import conftest  # noqa: F401
from .settings import *  # noqa: F403
