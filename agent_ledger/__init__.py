"""agent-ledger: an append-only, tamper-evident audit log for AI agent actions."""

from .ledger import Entry, Ledger, VerifyResult

__all__ = ["Ledger", "Entry", "VerifyResult"]
__version__ = "0.1.0"
