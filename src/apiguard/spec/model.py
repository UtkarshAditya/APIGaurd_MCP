"""Normalized, ``$ref``-resolved view of an OpenAPI spec.

Rules read this model, never raw OpenAPI, so spec quirks are handled once in
the loader. All strings here originate from the spec and are untrusted data.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

ParamLocation = Literal["path", "query", "header", "cookie"]
SecurityRequirement = dict[str, list[str]]


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class SchemaInfo(_Model):
    """The subset of a JSON Schema that rules inspect."""

    type: str | None = None
    format: str | None = None
    enum: list[Any] | None = None
    max_length: int | None = None
    minimum: float | None = None
    maximum: float | None = None


class Param(_Model):
    name: str
    location: ParamLocation
    required: bool = False
    schema_: SchemaInfo = Field(default_factory=SchemaInfo)


class ResponseInfo(_Model):
    """One documented response: its body schema and header names."""

    schema_: SchemaInfo | None = None
    headers: list[str] = Field(default_factory=list)


class SecurityScheme(_Model):
    """One entry of ``components.securitySchemes``."""

    type: str  # "http", "apiKey", "oauth2", "openIdConnect"
    scheme: str | None = None  # for type "http": "bearer", "basic"
    location: str | None = None  # for type "apiKey": "header", "query", "cookie"
    name: str | None = None  # for type "apiKey": the header, query or cookie name
    scopes: list[str] = Field(default_factory=list)


class Endpoint(_Model):
    id: str  # "GET /users/{id}" (stable key)
    method: str
    path: str
    operation_id: str | None = None
    tags: list[str] = Field(default_factory=list)
    params: list[Param] = Field(default_factory=list)
    request_body: SchemaInfo | None = None
    responses: dict[str, ResponseInfo] = Field(default_factory=dict)  # status code -> info
    # None = inherits the global requirement, [] = explicitly open.
    security: list[SecurityRequirement] | None = None
    deprecated: bool = False


class SpecModel(_Model):
    spec_id: str
    openapi_version: str
    servers: list[str] = Field(default_factory=list)
    security_schemes: dict[str, SecurityScheme] = Field(default_factory=dict)
    global_security: list[SecurityRequirement] = Field(default_factory=list)
    endpoints: list[Endpoint] = Field(default_factory=list)
