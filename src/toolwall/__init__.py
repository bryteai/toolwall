"""toolwall --- a 4-line firewall for indirect prompt injection on AI agents.

Public surface, kept deliberately small::

    from toolwall import toolwall, Policy, policy, Blocked

``toolwall``  --- the decorator.
``Policy``    --- the frozen security contract.
``policy``    --- the factory module: ``policy.web_fetch()``, ``policy.mcp()``, ...
``Blocked``   --- exception raised on enforcement.

Anything else under ``toolwall.*`` is internal and may change between minor
versions. The 4-line example in ``README.md`` is the only API contract.
"""

from __future__ import annotations

# Importing the detector subpackage registers the composite detector as the
# default for any @toolwall(...) call. Without this, the 4-line README
# example would silently leave IPI detection off.
from . import detect as _detect  # noqa: F401
from . import policy
from .decorator import Detector, toolwall
from .exceptions import Blocked, BudgetExceeded, PolicyViolation
from .policy import Policy

__version__ = "0.3.0"

__all__ = [
    "Blocked",
    "BudgetExceeded",
    "Detector",
    "Policy",
    "PolicyViolation",
    "__version__",
    "policy",
    "toolwall",
]
