from __future__ import annotations

from pathlib import Path

import pytest

from apiguard.config import CONFIG_ENV_VAR, AppConfig, ConfigError, load_config
from apiguard.models import Severity


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "apiguard.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_defaults_are_safe_without_a_file() -> None:
    cfg = load_config(env={})
    assert cfg.dynamic.allowed_hosts == ("localhost", "127.0.0.1", "::1")
    assert cfg.dynamic.allow_mutations is False
    assert cfg.dynamic.max_requests_per_run == 200
    assert cfg.dynamic.requests_per_second == 5
    assert cfg.dynamic.request_timeout_seconds == 10
    assert cfg.rules.disabled == ()
    assert cfg.rules.severity_overrides == {}
    assert cfg.suppressions == ()
    assert cfg.output_dir == Path("./apiguard-reports")


def test_default_database_path_is_expanded() -> None:
    cfg = load_config(env={})
    assert "~" not in str(cfg.database)
    assert cfg.database == Path("~/.apiguard/apiguard.db").expanduser()


def test_empty_file_gives_defaults(tmp_path: Path) -> None:
    assert load_config(write(tmp_path, "")) == AppConfig()


def test_partial_file_keeps_other_defaults(tmp_path: Path) -> None:
    cfg = load_config(write(tmp_path, "dynamic:\n  max_requests_per_run: 20\n"))
    assert cfg.dynamic.max_requests_per_run == 20
    assert cfg.dynamic.allow_mutations is False
    assert cfg.dynamic.allowed_hosts == ("localhost", "127.0.0.1", "::1")


def test_env_var_names_the_file(tmp_path: Path) -> None:
    path = write(tmp_path, "dynamic:\n  allowed_hosts: [staging.example.com]\n")
    cfg = load_config(env={CONFIG_ENV_VAR: str(path)})
    assert cfg.dynamic.allowed_hosts == ("staging.example.com",)


def test_explicit_path_wins_over_env_var(tmp_path: Path) -> None:
    path = write(tmp_path, "dynamic:\n  requests_per_second: 1\n")
    cfg = load_config(path, env={CONFIG_ENV_VAR: str(tmp_path / "missing.yaml")})
    assert cfg.dynamic.requests_per_second == 1


def test_reads_real_environment_by_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = write(tmp_path, "dynamic:\n  max_requests_per_run: 7\n")
    monkeypatch.setenv(CONFIG_ENV_VAR, str(path))
    assert load_config().dynamic.max_requests_per_run == 7


def test_allow_mutations_can_be_enabled_by_the_file(tmp_path: Path) -> None:
    cfg = load_config(write(tmp_path, "dynamic:\n  allow_mutations: true\n"))
    assert cfg.dynamic.allow_mutations is True


@pytest.mark.parametrize("value", ['"true"', "yes", "1", "on"])
def test_allow_mutations_requires_a_real_boolean(tmp_path: Path, value: str) -> None:
    with pytest.raises(ConfigError):
        load_config(write(tmp_path, f"dynamic:\n  allow_mutations: {value}\n"))


def test_named_but_missing_file_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="Cannot read"):
        load_config(env={CONFIG_ENV_VAR: str(tmp_path / "missing.yaml")})


def test_invalid_yaml_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not valid YAML"):
        load_config(write(tmp_path, "dynamic: [unclosed\n"))


def test_top_level_must_be_a_mapping(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="mapping"):
        load_config(write(tmp_path, "- a\n- b\n"))


@pytest.mark.parametrize(
    "text",
    [
        "unknown_key: 1\n",
        "dynamic:\n  allow_mutation: true\n",  # typo must not be ignored
        "dynamic:\n  max_requests_per_run: 0\n",
        "dynamic:\n  requests_per_second: -1\n",
        "rules:\n  severity_overrides:\n    API4-NO-429: catastrophic\n",
        "suppressions:\n  - rule: API4-NO-429\n    endpoint: GET /health\n",  # no reason
        'suppressions:\n  - rule: API4-NO-429\n    endpoint: GET /health\n    reason: ""\n',
    ],
)
def test_invalid_values_are_rejected(tmp_path: Path, text: str) -> None:
    with pytest.raises(ConfigError, match="invalid"):
        load_config(write(tmp_path, text))


def test_rules_and_suppressions_are_parsed(tmp_path: Path) -> None:
    cfg = load_config(
        write(
            tmp_path,
            "rules:\n"
            "  disabled: [API9-DEBUG-PATH]\n"
            "  severity_overrides:\n"
            "    API4-NO-429: high\n"
            "suppressions:\n"
            "  - rule: API4-NO-429\n"
            '    endpoint: "GET /health"\n'
            "    reason: Internal health check\n",
        )
    )
    assert cfg.rules.disabled == ("API9-DEBUG-PATH",)
    assert cfg.rules.severity_overrides == {"API4-NO-429": Severity.HIGH}
    assert cfg.suppressions[0].endpoint == "GET /health"
    assert cfg.suppressions[0].reason == "Internal health check"


def test_config_is_immutable() -> None:
    cfg = load_config(env={})
    with pytest.raises(Exception, match="frozen"):
        cfg.dynamic.allow_mutations = True  # type: ignore[misc]


def test_example_file_loads_and_is_safe(repo_root: Path) -> None:
    cfg = load_config(repo_root / "apiguard.yaml.example")
    assert cfg.dynamic.allow_mutations is False
    assert cfg.dynamic.allowed_hosts == ("localhost", "127.0.0.1")
    assert cfg.suppressions[0].rule == "API4-NO-429"
