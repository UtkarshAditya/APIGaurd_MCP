"""Configuration models and the loader for ``apiguard.yaml``.

The config file is user-owned and trusted. It is the only place where safety
limits live: the host allowlist, ``allow_mutations`` and the request budgets.
Nothing here can be set through a tool argument.

Path confinement checks (spec directories, report output) will be added here
alongside the features that need them.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, StrictBool, ValidationError, field_validator
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from apiguard.models import Severity

CONFIG_ENV_VAR = "APIGUARD_CONFIG"
DEFAULT_ALLOWED_HOSTS: tuple[str, ...] = ("localhost", "127.0.0.1", "::1")
DEFAULT_DATABASE = Path("~/.apiguard/apiguard.db")
DEFAULT_OUTPUT_DIR = Path("./apiguard-reports")


class ConfigError(Exception):
    """The config file is missing, unreadable or invalid."""


class _Model(BaseModel):
    # validate_default: defaults go through the same validators as file values,
    # so the default database path gets its "~" expanded too.
    model_config = ConfigDict(frozen=True, extra="forbid", validate_default=True)


class DynamicConfig(_Model):
    """Limits for dynamic probing. Safe by default."""

    allowed_hosts: tuple[str, ...] = DEFAULT_ALLOWED_HOSTS
    # StrictBool: only a real YAML boolean enables mutations, never "yes" or 1.
    allow_mutations: StrictBool = False
    max_requests_per_run: int = Field(default=200, gt=0)
    requests_per_second: float = Field(default=5, gt=0)
    request_timeout_seconds: float = Field(default=10, gt=0)


class RuleConfig(_Model):
    """Which rules run and at what severity."""

    disabled: tuple[str, ...] = ()
    severity_overrides: dict[str, Severity] = Field(default_factory=dict)


class Suppression(_Model):
    """A per-endpoint suppression; the reason is mandatory so exclusions stay visible."""

    rule: str
    endpoint: str
    reason: str = Field(min_length=1)


class AppConfig(_Model):
    """Top-level contents of ``apiguard.yaml``."""

    database: Path = DEFAULT_DATABASE
    output_dir: Path = DEFAULT_OUTPUT_DIR
    dynamic: DynamicConfig = Field(default_factory=DynamicConfig)
    rules: RuleConfig = Field(default_factory=RuleConfig)
    suppressions: tuple[Suppression, ...] = ()

    @field_validator("database", "output_dir")
    @classmethod
    def _expand_user(cls, value: Path) -> Path:
        return value.expanduser()


def load_config(
    path: str | Path | None = None,
    *,
    env: Mapping[str, str] | None = None,
) -> AppConfig:
    """Load the configuration.

    Resolution order: the explicit ``path``, then the file named by the
    ``APIGUARD_CONFIG`` environment variable, then built-in safe defaults. A file
    that is named but missing or invalid raises ``ConfigError`` rather than
    silently falling back to defaults.
    """
    environ = os.environ if env is None else env
    source = path if path is not None else (environ.get(CONFIG_ENV_VAR) or None)
    if source is None:
        return AppConfig()

    config_path = Path(source).expanduser()
    try:
        text = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Cannot read config file {config_path}: {exc}") from exc

    try:
        data: object = YAML(typ="safe", pure=True).load(text)
    except YAMLError as exc:
        raise ConfigError(f"Config file {config_path} is not valid YAML: {exc}") from exc

    if data is None:  # empty file
        return AppConfig()
    if not isinstance(data, dict):
        raise ConfigError(f"Config file {config_path} must contain a mapping at the top level")

    try:
        return AppConfig.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"Config file {config_path} is invalid: {exc}") from exc
