import argparse
import json
import platform
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote


def get_os_release(path="/etc/os-release"):
    data = {}

    with open(path, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line or "=" not in line:
                continue

            key, value = line.split("=", 1)
            data[key] = value.strip().strip('"')

    return data


def make_version(epoch, version, release):
    result = f"{version}-{release}"

    if epoch and epoch not in ("0", "(none)", "None"):
        result = f"{epoch}:{result}"

    return result


def make_purl(name, version, arch, distro):
    return (
        f"pkg:rpm/rocky/{quote(name, safe='')}"
        f"@{quote(version, safe='')}"
        f"?arch={quote(arch, safe='')}&distro={quote(distro, safe='')}"
    )


def collect_rpm_components(os_data):
    distro = f"{os_data.get('ID', 'rocky')}-{os_data.get('VERSION_ID', '')}"
    query_format = "%{NAME}|%{EPOCHNUM}|%{VERSION}|%{RELEASE}|%{ARCH}\\n"

    completed = subprocess.run(
        ["rpm", "-qa", "--queryformat", query_format],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    components = []

    for line in completed.stdout.splitlines():
        parts = line.split("|")

        if len(parts) != 5:
            continue

        name, epoch, version, release, arch = parts
        full_version = make_version(epoch, version, release)
        purl = make_purl(name, full_version, arch, distro)

        components.append({
            "type": "library",
            "bom-ref": purl,
            "name": name,
            "version": full_version,
            "purl": purl,
            "properties": [
                {
                    "name": "rpm:arch",
                    "value": arch
                },
                {
                    "name": "rpm:distro",
                    "value": distro
                }
            ]
        })

    components.sort(key=lambda item: item["name"].lower())
    return components


def build_bom():
    os_data = get_os_release()
    components = collect_rpm_components(os_data)

    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [
                {
                    "vendor": "custom",
                    "name": "task5_make_bom.py",
                    "version": "1.0"
                }
            ],
            "component": {
                "type": "operating-system",
                "name": os_data.get("PRETTY_NAME", "Rocky Linux"),
                "version": os_data.get("VERSION_ID", ""),
                "properties": [
                    {
                        "name": "os:id",
                        "value": os_data.get("ID", "")
                    },
                    {
                        "name": "os:arch",
                        "value": platform.machine()
                    }
                ]
            }
        },
        "components": components
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    bom = build_bom()

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(bom, file, ensure_ascii=False, indent=2)

    print(f"BOM file: {output_path}")
    print(f"Format: CycloneDX {bom['specVersion']}")
    print(f"Components: {len(bom['components'])}")


if __name__ == "__main__":
    main()
