import json
import platform
import re
import subprocess
from pathlib import Path


OUTPUT_PATH = Path("results/result_task_4.json")


def parse_os_release(path="/etc/os-release"):
    data = {}

    with open(path, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line or "=" not in line:
                continue

            key, value = line.split("=", 1)
            data[key] = value.strip().strip('"')

    version = data.get("VERSION", "")
    codename = None

    match = re.search(r"\((.*?)\)", version)
    if match:
        codename = match.group(1)

    description = data.get("PRETTY_NAME")
    if not description:
        description = f"{data.get('NAME', '')} {data.get('VERSION_ID', '')}".strip()

    os_info = {
        "name": data.get("NAME", ""),
        "version": version,
        "arch": platform.machine(),
        "id": data.get("ID", ""),
        "version_id": data.get("VERSION_ID", ""),
        "description": description,
    }

    if codename:
        os_info["codename"] = codename

    return os_info


def first_sentence(text):
    text = text.strip()

    if not text:
        return ""

    match = re.match(r"(.+?[.!?])(\s|$)", text)
    if match:
        return match.group(1).strip()

    return text.splitlines()[0].strip()


def collect_packages():
    query_format = "%{NAME}|%{VERSION}-%{RELEASE}|%{ARCH}|%{SUMMARY}|%{SIZE}\\n"

    completed = subprocess.run(
        ["rpm", "-qa", "--queryformat", query_format],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    packages = []

    for line in completed.stdout.splitlines():
        parts = line.split("|", 4)

        if len(parts) != 5:
            continue

        name, version, arch, summary, size = parts

        package = {
            "name": name,
            "version": version,
            "arch": arch,
            "description": first_sentence(summary),
        }

        if size.isdigit():
            package["size"] = int(size)

        packages.append(package)

    packages.sort(key=lambda item: item["name"].lower())

    return packages


def main():
    result = {
        "os": parse_os_release(),
        "packages": collect_packages(),
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_PATH.open("w", encoding="utf-8") as file:
        json.dump(result, file, ensure_ascii=False, indent=2)

    print(f"Result file: {OUTPUT_PATH}")
    print(f"OS: {result['os']['description']}")
    print(f"Architecture: {result['os']['arch']}")
    print(f"Packages: {len(result['packages'])}")


if __name__ == "__main__":
    main()
