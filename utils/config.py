"""Runtime settings (django-constance), editable in Django admin under "Config". See docs/runtime-config.md."""

from constance import config


def code_set(name: str) -> set[str]:
    """A comma-separated list setting, as a set of lowercase codes with the blanks dropped."""
    return {code.strip().lower() for code in getattr(config, name).split(",")} - {""}
