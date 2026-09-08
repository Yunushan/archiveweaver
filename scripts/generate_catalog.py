#!/usr/bin/env python3
"""Generate runtime catalog JSON and human-readable reference pages."""

from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from archiveweaver.catalog_source import catalog  # noqa: E402


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.rstrip() + "\n", encoding="utf-8")


def markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    result = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    result.extend("| " + " | ".join(row) + " |" for row in rows)
    return "\n".join(result)


def mode_matrix(solution: dict, runtimes: list[dict]) -> str:
    rows = []
    for runtime in runtimes:
        status = solution["mode_support"][runtime["id"]]
        policy = runtime["topology"]
        rows.append([
            runtime["name"],
            status,
            policy["1"],
            policy["2"],
            policy["3"],
            policy["3+"],
        ])
    return markdown_table(["Mode", "Product fit", "1 node", "2 nodes", "3 nodes", "3+ nodes"], rows)


def solution_page(solution: dict, runtimes: list[dict], formats: dict) -> str:
    format_rows = []
    for group in solution["format_profiles"]:
        item = formats[group]
        format_rows.append([item["label"], item["extensions"]])
    notes = "\n".join(f"- {note}" for note in solution["notes"]) or "- No product-specific caveat recorded yet."
    image = solution["image_hint"] or "No image pinned; use the upstream release or approved internal registry."
    parts = [
        f"# {solution['name']}\n\n",
        "ArchiveWeaver adapter facts for planning, checking and repair. Product behavior remains governed by the upstream release documentation.\n\n",
        f"- **Category:** {solution['category']}\n",
        f"- **License:** {solution['license']}\n",
        f"- **Upstream repository:** {solution['upstream_repo']}\n",
        f"- **Canonical source repository:** {solution['source_repo']}\n",
        f"- **Official documentation:** {solution['official_docs']}\n",
        f"- **Homepage:** {solution['homepage']}\n",
        f"- **Default HTTP port:** {solution['health']['default_port']}\n",
        f"- **Container image hint:** `{image}`\n\n",
        "## Architecture components\n\n",
        "\n".join(f"- {component}" for component in solution["architecture_components"]),
        "\n\n## Dependencies\n\n",
        "\n".join(f"- {dependency}" for dependency in solution["dependencies"]),
        "\n\n## Mode and topology matrix\n\n",
        mode_matrix(solution, runtimes),
        "\n\n`native` and `validated` refer to an upstream or repository-backed path. `portable` means ArchiveWeaver can render and check the runtime pattern, but the product's own HA guarantees and state model must be validated. `conditional` requires an explicit design review. `not-recommended` is intentionally blocked by the planner unless an exception is documented.\n\n",
        "## Health checks\n\n",
        "\n".join(f"- `{check}`" for check in solution["health"]["checks"]),
        "\n\n",
        f"Service aliases: `{', '.join(solution['health']['service_aliases'])}`\n\n",
        f"HTTP paths: `{', '.join(solution['health']['http_paths'])}`\n\n",
        "## Format families\n\n",
        markdown_table(["Family", "Extensions in the ArchiveWeaver catalog"], format_rows),
        "\n\n",
        "The format list is an operational catalog, not a promise that every product previews, OCRs, indexes, or preserves every extension. Intake and storage are separate from transformation and browser preview.\n\n",
        "## Product-specific notes\n\n",
        notes,
        "\n",
    ]
    return "".join(parts)


def main() -> None:
    data = catalog()
    data_dir = ROOT / "src" / "archiveweaver" / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    write(data_dir / "catalog.json", json.dumps(data, indent=2, ensure_ascii=False))
    for key in ("solutions", "runtimes", "operating_systems", "formats"):
        write(data_dir / f"{key}.json", json.dumps(data[key], indent=2, ensure_ascii=False))

    solution_rows = []
    for solution in data["solutions"]:
        solution_rows.append([
            f"[{solution['name']}](../solutions/{solution['id']}.md)",
            solution["category"],
            solution["license"],
            solution["mode_support"]["raw"],
            solution["mode_support"]["docker"],
            solution["upstream_repo"],
        ])
        write(ROOT / "docs" / "solutions" / f"{solution['id']}.md", solution_page(solution, data["runtimes"], data["formats"]))

    write(
        ROOT / "docs" / "reference" / "solutions-catalog.md",
        "# Solution catalog\n\n"
        "This page is generated from `src/archiveweaver/catalog_source.py`. Run `python scripts/generate_catalog.py` after changing catalog facts.\n\n"
        + markdown_table(["Solution", "Category", "License", "Raw", "Docker", "Upstream"], solution_rows),
    )

    support_headers = ["Solution"] + [runtime["id"] for runtime in data["runtimes"]]
    support_rows = [
        [solution["name"]] + [solution["mode_support"][runtime["id"]] for runtime in data["runtimes"]]
        for solution in data["solutions"]
    ]
    write(
        ROOT / "docs" / "reference" / "support-matrix.md",
        "# Product support matrix\n\n"
        "This page is generated from `src/archiveweaver/catalog_source.py`. Product fit describes the upstream/repository path recorded for the mode; runtime topology policy is documented separately in [runtime-matrix.md](../deployment/runtime-matrix.md).\n\n"
        + markdown_table(support_headers, support_rows),
    )

    source_rows = []
    for solution in data["solutions"]:
        source_rows.append([
            solution["name"],
            solution["upstream_repo"],
            solution["source_repo"],
            solution["official_docs"],
            solution["homepage"],
        ])
    write(
        ROOT / "docs" / "reference" / "upstream-sources.md",
        "# Upstream sources\n\n"
        "Links below are maintained as catalog facts and should be rechecked when a product release is pinned. GitHub is not the canonical forge for every product; Maarch, Mayan EDMS, Asalae, and SeedDMS use other official channels.\n\n"
        + markdown_table(["Product", "Upstream / project page", "Canonical source", "Official docs", "Homepage"], source_rows),
    )

    format_rows = [[item["label"], item["extensions"], item["mime_examples"]] for item in data["formats"].values()]
    write(
        ROOT / "docs" / "reference" / "formats.md",
        "# File-format catalog\n\n"
        "ArchiveWeaver treats file acceptance, preservation, indexing, OCR, derivative generation, and browser preview as different capabilities. The extension inventory below is intentionally broad for planning and validation. A product adapter must declare the actual capabilities of the pinned release.\n\n"
        + markdown_table(["Family", "Extensions", "Representative MIME types"], format_rows)
        + "\n\n## Operational policy\n\n"
        "- Do not reject a file solely from its extension; verify magic bytes and MIME detection where the application supports it.\n"
        "- Keep the original bitstream immutable and record SHA-256 (or stronger) fixity.\n"
        "- Store a preservation event for normalization, OCR, virus scanning, preview generation, and failed transformations.\n"
        "- Product-specific preview/OCR support may require ImageMagick, FFmpeg, LibreOffice, Apache Tika, ExifTool, Ghostscript, Tesseract, MediaInfo, or a dedicated format registry.\n"
        "- Add new extensions through a pull request with an upstream reference and a test fixture.\n",
    )

    format_matrix_rows = [
        [solution["name"], ", ".join(solution["format_profiles"])]
        for solution in data["solutions"]
    ]
    write(
        ROOT / "docs" / "reference" / "format-matrix.md",
        "# Product format-family matrix\n\n"
        "This page is generated from `src/archiveweaver/catalog_source.py`. It maps each product to the broad format families it should be tested against. The authoritative extension inventory is [formats.md](formats.md); an extension in that inventory is not automatically a preview, OCR, indexing, or preservation guarantee for every product.\n\n"
        + markdown_table(["Solution", "Catalog format families"], format_matrix_rows),
    )

    os_rows = [[os["name"], os["family"], os["tier"]] for os in data["operating_systems"]]
    write(
        ROOT / "docs" / "deployment" / "os-matrix.md",
        "# Operating-system matrix\n\n"
        "The matrix describes the ArchiveWeaver host baseline. It does not override product-specific support policies. Always test the exact application release, dependency versions, kernel, SELinux/AppArmor policy, storage driver, and CPU architecture.\n\n"
        + markdown_table(["Operating system", "Family", "ArchiveWeaver baseline"], os_rows)
        + "\n\n## Tiers\n\n"
        "- **preferred:** default target for new production automation.\n"
        "- **validated-base:** supported host baseline; application release validation is still required.\n"
        "- **forward-validate:** included for early validation and future-proofing; do not silently promote to production without a release test.\n"
        "- **legacy-conditional:** usable when a pinned product requires it, but avoid introducing new workloads.\n",
    )


if __name__ == "__main__":
    main()
