# SPDX-License-Identifier: Apache-2.0
"""The existing one-response HTTPS review, with no effectiveness claims from presence."""

from datetime import datetime, timedelta
from typing import TypedDict
from urllib.parse import urlsplit

from godseye.inventory import utc_now
from godseye.network import Response, head


class Check(TypedDict):
    name: str
    status: str
    detail: str


def evaluate(response: Response, kind: str, now: datetime) -> list[Check]:
    checks: list[Check] = [
        {
            "name": "HTTP response",
            "status": "observed",
            "detail": f"HEAD returned HTTP {response.status}. Redirects were not followed.",
        }
    ]
    if response.certificate_expiry is not None:
        expiry = response.certificate_expiry
        checks.append(
            {
                "name": "TLS certificate",
                "status": "review" if expiry < now + timedelta(days=30) else "pass",
                "detail": "Certificate expires "
                + expiry.strftime("%Y-%m-%d")
                + ". Connection used normal certificate verification.",
            }
        )
    for name, explanation in (
        (
            "Strict-Transport-Security",
            "Check that the policy has an appropriate max-age and domain scope.",
        ),
        ("X-Content-Type-Options", "Expected nosniff to reduce MIME-type confusion."),
    ):
        value = response.headers.get(name.lower(), "")
        status = "observed" if value else "review"
        detail = ("Header is present. " if value else "Header is absent. ") + explanation
        if name == "X-Content-Type-Options":
            status = "pass" if value.strip().lower() == "nosniff" else "review"
        checks.append({"name": name, "status": status, "detail": detail})
    if kind in {"website", "application"}:
        present = bool(response.headers.get("content-security-policy"))
        checks.append(
            {
                "name": "Browser content policy",
                "status": "observed" if present else "review",
                "detail": (
                    "Content-Security-Policy is present; "
                    "policy effectiveness has not been evaluated."
                )
                if present
                else "Content-Security-Policy is absent on this response. Review whether "
                "this endpoint serves browser content.",
            }
        )
    checks.append(
        {
            "name": "Coverage",
            "status": "limited",
            "detail": "One unauthenticated HEAD response only. No crawling, injection tests, "
            "authenticated routes or application-logic verification.",
        }
    )
    return checks


async def inspect(target: str, kind: str) -> list[Check]:
    try:
        port = urlsplit(target).port
    except ValueError as error:
        raise ValueError(
            "use an HTTPS URL without credentials, query parameters or fragments"
        ) from error
    if port not in {None, 443}:
        raise ValueError("only HTTPS port 443 is supported")
    return evaluate(await head(target), kind, utc_now())
