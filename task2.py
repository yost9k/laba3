import json
import os
import re
from pathlib import Path
from typing import Any

import requests
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version


INPUT_PATH = Path("results/result_task_1.json")
OUTPUT_PATH = Path("results/result_task_2.json")
GITHUB_GRAPHQL_URL = "https://api.github.com/graphql"

ECOSYSTEM_MAP = {
    "pypi": "PIP"
}

QUERY = """
query($ecosystem: SecurityAdvisoryEcosystem!, $package: String!, $after: String) {
  securityVulnerabilities(
    first: 100,
    after: $after,
    ecosystem: $ecosystem,
    package: $package,
    orderBy: {field: UPDATED_AT, direction: DESC}
  ) {
    pageInfo {
      hasNextPage
      endCursor
    }
    nodes {
      package {
        ecosystem
        name
      }
      vulnerableVersionRange
      firstPatchedVersion {
        identifier
      }
      severity
      advisory {
        ghsaId
        summary
        permalink
      }
    }
  }
}
"""


def get_token() -> str:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise SystemExit(
            "Не найден GITHUB_TOKEN. Сначала выполни export GITHUB_TOKEN."
        )
    return token


def graphql_request(token: str, variables: dict[str, Any]) -> dict[str, Any]:
    response = requests.post(
        GITHUB_GRAPHQL_URL,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
        },
        json={
            "query": QUERY,
            "variables": variables,
        },
        timeout=30,
    )

    if response.status_code != 200:
        raise SystemExit(f"GitHub API error {response.status_code}: {response.text}")

    data = response.json()

    if "errors" in data:
        raise SystemExit(
            "GraphQL errors: "
            + json.dumps(data["errors"], ensure_ascii=False, indent=2)
        )

    return data


def normalize_range(version_range: str) -> str:
    cleaned = version_range.strip()
    cleaned = re.sub(r"\s+", " ", cleaned)
    cleaned = re.sub(r"([<>=!~]=?)\s+", r"\1", cleaned)
    return cleaned


def is_version_vulnerable(version: str, vulnerable_range: str) -> bool:
    if not version or not vulnerable_range:
        return False

    try:
        current_version = Version(version)
        specifier = SpecifierSet(normalize_range(vulnerable_range))
        return current_version in specifier
    except (InvalidVersion, InvalidSpecifier):
        return False


def fetch_package_vulnerabilities(
    token: str,
    package_name: str,
    ecosystem: str,
) -> list[dict[str, Any]]:
    github_ecosystem = ECOSYSTEM_MAP.get(ecosystem.lower())

    if github_ecosystem is None:
        return []

    vulnerabilities = []
    after = None

    while True:
        data = graphql_request(
            token,
            {
                "ecosystem": github_ecosystem,
                "package": package_name,
                "after": after,
            },
        )

        connection = data["data"]["securityVulnerabilities"]
        vulnerabilities.extend(connection["nodes"])

        page_info = connection["pageInfo"]
        if not page_info["hasNextPage"]:
            break

        after = page_info["endCursor"]

    return vulnerabilities


def get_secure_version(vulnerabilities: list[dict[str, Any]]) -> str | None:
    patched_versions = []

    for vuln in vulnerabilities:
        patched = vuln.get("first_patched_version")
        if not patched:
            continue

        try:
            patched_versions.append(Version(patched))
        except InvalidVersion:
            pass

    if not patched_versions:
        return None

    return str(max(patched_versions))


def main() -> None:
    token = get_token()

    if not INPUT_PATH.exists():
        raise SystemExit(f"Не найден {INPUT_PATH}. Сначала выполни задачу 1.")

    with INPUT_PATH.open("r", encoding="utf-8") as file:
        dependencies = json.load(file)

    result = []

    for dep in dependencies:
        name = dep["name"]
        version = dep["version"]
        ecosystem = dep["ecosystem"]

        print(f"Checking {name} {version} ({ecosystem})...")

        all_vulnerabilities = fetch_package_vulnerabilities(token, name, ecosystem)
        applicable_vulnerabilities = []

        for vuln in all_vulnerabilities:
            vulnerable_range = vuln.get("vulnerableVersionRange") or ""

            if not is_version_vulnerable(version, vulnerable_range):
                continue

            advisory = vuln["advisory"]
            first_patched = vuln.get("firstPatchedVersion")
            first_patched_version = (
                first_patched["identifier"] if first_patched else None
            )

            applicable_vulnerabilities.append(
                {
                    "name": advisory["ghsaId"],
                    "summary": advisory.get("summary"),
                    "severity": vuln.get("severity"),
                    "vulnerable_range": vulnerable_range,
                    "first_patched_version": first_patched_version,
                    "url": advisory.get("permalink"),
                }
            )

        secure_version = get_secure_version(applicable_vulnerabilities)

        result.append(
            {
                "name": dep["name"],
                "version": dep["version"],
                "ecosystem": dep["ecosystem"],
                "url": dep["url"],
                "purl": dep["purl"],
                "vulnerabilities": applicable_vulnerabilities,
                "secure_version": secure_version,
            }
        )

        print(f"  applicable vulnerabilities: {len(applicable_vulnerabilities)}")

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_PATH.open("w", encoding="utf-8") as file:
        json.dump(result, file, ensure_ascii=False, indent=2)

    total_vulns = sum(len(dep["vulnerabilities"]) for dep in result)
    vulnerable_packages = sum(1 for dep in result if dep["vulnerabilities"])

    print(f"Result file: {OUTPUT_PATH}")
    print(f"Total packages: {len(result)}")
    print(f"Vulnerable packages: {vulnerable_packages}")
    print(f"Total applicable vulnerabilities: {total_vulns}")


if __name__ == "__main__":
    main()
