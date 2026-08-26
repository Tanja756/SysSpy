"""SysSpy — lightweight spyware / intrusion detector for Linux.

This package provides detectors that inspect processes, network connections,
persistence mechanisms, filesystem activity, input capture and kernel modules.
It is a helper, not a replacement for a real antivirus / EDR product.
"""

from .finding import Finding, Severity

__all__ = ["Finding", "Severity"]
