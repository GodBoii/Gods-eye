# SPDX-License-Identifier: Apache-2.0
"""Legacy JSON validation without coercion or input values in error responses."""

import json
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError, model_validator


class InvalidRequest(ValueError):
    pass


def parse_json(data: bytes) -> Any:
    """Reject non-JSON numbers; duplicate keys retain Go's last-value behavior."""

    def reject_constant(_: str) -> None:
        raise InvalidRequest("Invalid JSON request")

    try:
        return json.loads(data, parse_constant=reject_constant)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise InvalidRequest("Invalid JSON request") from error


class RequestModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", populate_by_name=False)

    @model_validator(mode="before")
    @classmethod
    def go_null_defaults(cls, value: Any) -> Any:
        # encoding/json leaves non-pointer scalar fields zero-valued for null.
        if value is None:
            return {}
        if isinstance(value, Mapping):
            fields = {key.casefold(): key for key in cls.model_fields}
            return {
                fields.get(key.casefold(), key): cls.model_fields[fields[key.casefold()]].default
                if item is None and key.casefold() in fields
                else item
                for key, item in value.items()
            }
        return value


class AssetRequest(RequestModel):
    name: str = ""
    kind: str = ""
    target: str = ""
    owner: str = ""


class RunRequest(RequestModel):
    target: str = ""
    kind: str = ""
    authorized: bool = False


def decode_request[T: RequestModel](data: bytes, model: type[T]) -> T:
    if len(data) > 16 << 10:
        raise InvalidRequest("Invalid JSON request")
    # Go distinguishes a second JSON document from malformed first input.
    try:
        value = parse_json(data)
    except InvalidRequest as error:
        trailing = False
        try:
            decoded = data.decode("utf-8")
            _, end = json.JSONDecoder().raw_decode(decoded.lstrip())
            if decoded.lstrip()[end:].strip():
                trailing = True
        except (UnicodeError, ValueError, RecursionError):
            pass
        if trailing:
            raise InvalidRequest("Expected one JSON object") from error
        raise error
    try:
        return model.model_validate(value)
    except ValidationError as error:
        raise InvalidRequest("Invalid JSON request") from error


def timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError) as error:
        raise ValueError("invalid timestamp") from error
    if parsed.tzinfo is None or parsed.year == 1:
        raise ValueError("invalid timestamp")
    return parsed
