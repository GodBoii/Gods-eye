# SPDX-License-Identifier: Apache-2.0
"""Collect installed runtime license texts. Run in the locked development environment."""

import importlib.metadata
from pathlib import Path

from packaging.requirements import Requirement


def main() -> None:
    pending = ["fastapi", "pydantic", "starlette", "uvicorn", "protobuf"]
    found: dict[str, importlib.metadata.Distribution] = {}
    while pending:
        name = pending.pop().lower().replace("_", "-")
        if name in found:
            continue
        distribution = importlib.metadata.distribution(name)
        found[name] = distribution
        for raw in distribution.requires or []:
            requirement = Requirement(raw)
            if requirement.marker is None or requirement.marker.evaluate({"extra": ""}):
                pending.append(requirement.name)
    sections = [
        "Python candidate runtime dependency notices\n"
        "Generated from the installed Windows development environment.\n"
        "Exact versions and artifact hashes: backend/requirements.lock.\n"
        "Go and frontend notices remain separately applicable during migration.\n"
    ]
    for name, distribution in sorted(found.items()):
        metadata = distribution.metadata
        sections.append(f"\n{'=' * 72}\n{name} {distribution.version}\n")
        for key in ("License-Expression", "License", "Home-page"):
            value = metadata.get(key)
            if value:
                sections.append(f"{key}: {value}\n")
        licenses = [
            item
            for item in distribution.files or []
            if ".dist-info/" in str(item)
            and (
                "/licenses/" in str(item).lower()
                or item.name.lower().startswith(("license", "copying", "notice"))
            )
        ]
        if not licenses:
            raise RuntimeError(f"No installed license text for {name}")
        for item in sorted(licenses, key=str):
            sections.append(f"\n--- {item.name} ---\n")
            sections.append(Path(distribution.locate_file(item)).read_text(encoding="utf-8") + "\n")
    destination = Path(__file__).resolve().parents[2] / "licenses/python-libraries.txt"
    destination.write_text("".join(sections), encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
