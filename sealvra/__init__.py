"""Sealvra v0.1 — personal edition, local-only, no sync ever.

Product name Sealvra, command ``sealvra`` (the name is the owner-confirmed
one; ``keyholder`` was retired by the v0.2 Phase 3 rename pass). This package is the
command-line surface (W10). It never holds a long-lived key longer than
the transient moment of import/rotation, never prints a key value, and
never offers a path to display a stored key again.

Tier note (CONTRACT §10): the CLI talks to the daemon over a loopback
socket. On Linux/Windows that does NOT separate same-user processes
(Tier B) — only macOS keychain access groups do that, and they cannot
be proven on Linux. Same-user malware / a compromised OS account is
out of scope by design.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
