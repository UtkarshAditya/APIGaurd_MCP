from __future__ import annotations

import pytest
from pydantic import ValidationError

from apiguard.spec.loader import load_spec
from apiguard.spec.model import Endpoint, Param, SchemaInfo, SecurityScheme, SpecModel


def test_endpoint_distinguishes_inherited_from_explicitly_open_security() -> None:
    inherited = Endpoint(id="GET /users/{id}", method="GET", path="/users/{id}")
    explicitly_open = Endpoint(
        id="DELETE /users/{id}", method="DELETE", path="/users/{id}", security=[]
    )
    assert inherited.security is None
    assert explicitly_open.security == []


def test_spec_model_round_trips_through_json() -> None:
    spec = SpecModel(
        spec_id="s1",
        openapi_version="3.0.3",
        servers=["https://api.example.com"],
        security_schemes={"bearerAuth": SecurityScheme(type="http", scheme="bearer")},
        global_security=[{"bearerAuth": []}],
        endpoints=[
            Endpoint(
                id="GET /users/{id}",
                method="GET",
                path="/users/{id}",
                params=[
                    Param(
                        name="id",
                        location="path",
                        required=True,
                        schema_=SchemaInfo(type="string", max_length=36),
                    )
                ],
            )
        ],
    )
    assert SpecModel.model_validate_json(spec.model_dump_json()) == spec


def test_param_location_is_restricted() -> None:
    with pytest.raises(ValidationError):
        Param.model_validate({"name": "id", "location": "body"})


def test_loader_is_not_implemented_yet() -> None:
    with pytest.raises(NotImplementedError):
        load_spec("tests/fixtures/clean.yaml")
