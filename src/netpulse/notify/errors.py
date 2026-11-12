from __future__ import annotations


class NotifyError(Exception):
    """A notification could not be delivered. The message never holds a secret."""
