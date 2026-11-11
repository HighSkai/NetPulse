"""One way to refuse a form (plan section 32).

Every form shows a refusal the same way: a summary at the top of the form,
linked to the field; the field marked invalid and described by its message;
and what was typed kept. A form answers 422 when it is refused for what was
typed. The messages name their field, as the domain's do ("name is required",
"Filter: at most 200 characters"), and each form lists which words point at
which of its fields.
"""

from __future__ import annotations

import re
from typing import ClassVar


class Refusable:
    """Mixed into a form dataclass that has `error` and `error_field` fields, both defaulting to None."""

    # (field, pattern), checked in order; the first pattern found in the message names the field.
    FIELDS: ClassVar[tuple[tuple[str, str], ...]] = ()

    error: str | None
    error_field: str | None

    def fail(self, problem: Exception | str):
        message = str(problem)
        self.error = message[:1].upper() + message[1:]
        self.error_field = field_of(message, self.FIELDS)
        return self


def field_of(message: str, fields: tuple[tuple[str, str], ...]) -> str | None:
    """The field a message is about, or None when it is about the whole form."""
    return next((field for field, pattern in fields if re.search(pattern, message, re.I)), None)
