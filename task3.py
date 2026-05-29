import csv
import json
from pathlib import Path


INPUT_PATH = Path("results/result_task_2.json")
CSV_OUTPUT_PATH = Path("results/result_task_3.csv")
MD_OUTPUT_PATH = Path("results/result_task_3.md")

SEVERITIES = ["LOW", "MODERATE", "HIGH", "CRITICAL"]


def make_strategy(name: str, secure_version: str | None, total_vulns: int) -> str:
    if total_vulns == 0:
        return "Уязвимости не выявлены, обновление не требуется."

    if secure_version:
        return (
            f"Обновить пакет {name} до версии {secure_version} или выше. "
            "Перед обновлением проверить совместимость с Flask 2.0.2."
        )

    return (
        f"Проверить актуальные рекомендации по пакету {name}; "
        "исправленная версия не указана в advisory."
    )


def count_severities(vulnerabilities: list[dict]) -> dict[str, int]:
    counts = {severity: 0 for severity in SEVERITIES}

    for vuln in vulnerabilities:
        severity = str(vuln.get("severity", "")).upper()
        if severity in counts:
            counts[severity] += 1

    return counts


def make_markdown_table(rows: list[dict]) -> str:
    headers = [
        "Dependency",
        "Version",
        "Ecosystem",
        "LOW",
        "MODERATE",
        "HIGH",
        "CRITICAL",
        "Total",
        "Secure version",
        "Strategy",
    ]

    lines = []
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("|" + "|".join(["---"] * len(headers)) + "|")

    for row in rows:
        lines.append(
            "| "
            + " | ".join(
                [
                    row["name"],
                    row["version"],
                    row["ecosystem"],
                    str(row["low"]),
                    str(row["moderate"]),
                    str(row["high"]),
                    str(row["critical"]),
                    str(row["total"]),
                    row["secure_version"] or "-",
                    row["strategy"],
                ]
            )
            + " |"
        )

    return "\n".join(lines) + "\n"


def main() -> None:
    if not INPUT_PATH.exists():
        raise SystemExit(f"Не найден файл {INPUT_PATH}. Сначала выполни задачу 2.")

    with INPUT_PATH.open("r", encoding="utf-8") as file:
        dependencies = json.load(file)

    rows = []

    for dep in dependencies:
        vulnerabilities = dep.get("vulnerabilities", [])

        if not vulnerabilities:
            continue

        counts = count_severities(vulnerabilities)
        total = sum(counts.values())

        row = {
            "name": dep["name"],
            "version": dep["version"],
            "ecosystem": dep["ecosystem"],
            "low": counts["LOW"],
            "moderate": counts["MODERATE"],
            "high": counts["HIGH"],
            "critical": counts["CRITICAL"],
            "total": total,
            "secure_version": dep.get("secure_version"),
            "strategy": make_strategy(dep["name"], dep.get("secure_version"), total),
        }

        rows.append(row)

    rows.sort(key=lambda item: item["total"], reverse=True)

    CSV_OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with CSV_OUTPUT_PATH.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "name",
                "version",
                "ecosystem",
                "low",
                "moderate",
                "high",
                "critical",
                "total",
                "secure_version",
                "strategy",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    with MD_OUTPUT_PATH.open("w", encoding="utf-8") as file:
        file.write(make_markdown_table(rows))

    print(f"CSV result: {CSV_OUTPUT_PATH}")
    print(f"Markdown result: {MD_OUTPUT_PATH}")
    print(f"Vulnerable dependencies: {len(rows)}")

    for row in rows:
        print(
            f"- {row['name']} {row['version']}: "
            f"{row['total']} vulnerabilities "
            f"(LOW={row['low']}, MODERATE={row['moderate']}, "
            f"HIGH={row['high']}, CRITICAL={row['critical']}), "
            f"secure version: {row['secure_version'] or '-'}"
        )


if __name__ == "__main__":
    main()
