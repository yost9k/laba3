import json
from pathlib import Path


RESULT_PATH = Path("results/result_task_5_compare.json")


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def inventory_records(path):
    data = load_json(path)
    records = []

    for package in data.get("packages", []):
        records.append({
            "name": package.get("name", ""),
            "version": package.get("version", ""),
            "arch": package.get("arch", ""),
            "record_id": f"{package.get('name', '')}|{package.get('version', '')}|{package.get('arch', '')}",
        })

    return records


def bom_records(path):
    data = load_json(path)
    records = []

    for component in data.get("components", []):
        records.append({
            "name": component.get("name", ""),
            "version": component.get("version", ""),
            "purl": component.get("purl", ""),
            "record_id": component.get("purl", "") or f"{component.get('name', '')}|{component.get('version', '')}",
        })

    return records


def latest_by_name(records):
    result = {}

    for record in records:
        result[record["name"]] = record

    return result


def scan_stats(path):
    data = load_json(path)

    vulnerability_ids = set()
    vulnerable_packages = set()

    def walk(obj, current_package=None):
        if isinstance(obj, dict):
            package_name = current_package

            package = obj.get("package")
            if isinstance(package, dict):
                package_name = (
                    package.get("name")
                    or package.get("purl")
                    or package.get("id")
                    or current_package
                )

            vulnerabilities = obj.get("vulnerabilities")
            if isinstance(vulnerabilities, list):
                for vuln in vulnerabilities:
                    if isinstance(vuln, dict):
                        vuln_id = (
                            vuln.get("id")
                            or vuln.get("name")
                            or vuln.get("ghsaId")
                            or str(vuln)
                        )
                    else:
                        vuln_id = str(vuln)

                    vulnerability_ids.add(vuln_id)

                    if package_name:
                        vulnerable_packages.add(package_name)

            for value in obj.values():
                walk(value, package_name)

        elif isinstance(obj, list):
            for item in obj:
                walk(item, current_package)

    walk(data)

    return {
        "vulnerability_count": len(vulnerability_ids),
        "vulnerable_package_count": len(vulnerable_packages),
        "vulnerability_ids": sorted(vulnerability_ids),
        "vulnerable_packages": sorted(vulnerable_packages),
    }


def compare_records(before_records, after_records):
    before_record_ids = {record["record_id"] for record in before_records}
    after_record_ids = {record["record_id"] for record in after_records}

    before_by_name = latest_by_name(before_records)
    after_by_name = latest_by_name(after_records)

    before_names = set(before_by_name)
    after_names = set(after_by_name)

    added_names = sorted(after_names - before_names)
    removed_names = sorted(before_names - after_names)

    changed_versions = []

    for name in sorted(before_names & after_names):
        before_version = before_by_name[name]["version"]
        after_version = after_by_name[name]["version"]

        if before_version != after_version:
            changed_versions.append({
                "name": name,
                "before_version": before_version,
                "after_version": after_version,
            })

    return {
        "before_record_count": len(before_records),
        "after_record_count": len(after_records),
        "before_unique_name_count": len(before_names),
        "after_unique_name_count": len(after_names),
        "added_record_count": len(after_record_ids - before_record_ids),
        "removed_record_count": len(before_record_ids - after_record_ids),
        "added_unique_name_count": len(added_names),
        "removed_unique_name_count": len(removed_names),
        "changed_version_count": len(changed_versions),
        "added_unique_names": added_names,
        "removed_unique_names": removed_names,
        "changed_versions": changed_versions,
    }


def compare_inventory_and_bom(inventory_records_list, bom_records_list):
    inventory_ids = {record["record_id"] for record in inventory_records_list}
    bom_ids = {record["record_id"] for record in bom_records_list}

    inventory_names = {record["name"] for record in inventory_records_list}
    bom_names = {record["name"] for record in bom_records_list}

    return {
        "inventory_record_count": len(inventory_records_list),
        "bom_component_count": len(bom_records_list),
        "inventory_unique_name_count": len(inventory_names),
        "bom_unique_name_count": len(bom_names),
        "only_in_inventory_by_name_count": len(inventory_names - bom_names),
        "only_in_bom_by_name_count": len(bom_names - inventory_names),
        "only_in_inventory_by_record_count": len(inventory_ids - bom_ids),
        "only_in_bom_by_record_count": len(bom_ids - inventory_ids),
        "only_in_inventory_by_name": sorted(inventory_names - bom_names),
        "only_in_bom_by_name": sorted(bom_names - inventory_names),
    }


def main():
    inv_before = inventory_records("results/result_task_4_before.json")
    inv_after = inventory_records("results/result_task_4_after.json")

    bom_before = bom_records("results/bom_before.cdx.json")
    bom_after = bom_records("results/bom_after.cdx.json")

    scan_before = scan_stats("results/scan_before.json")
    scan_after = scan_stats("results/scan_after.json")

    result = {
        "inventory_comparison": compare_records(inv_before, inv_after),
        "bom_comparison": compare_records(bom_before, bom_after),
        "osv_scan_comparison": {
            "before": {
                "vulnerability_count": scan_before["vulnerability_count"],
                "vulnerable_package_count": scan_before["vulnerable_package_count"],
            },
            "after": {
                "vulnerability_count": scan_after["vulnerability_count"],
                "vulnerable_package_count": scan_after["vulnerable_package_count"],
            },
            "fixed_vulnerabilities": sorted(
                set(scan_before["vulnerability_ids"]) - set(scan_after["vulnerability_ids"])
            ),
            "new_vulnerabilities": sorted(
                set(scan_after["vulnerability_ids"]) - set(scan_before["vulnerability_ids"])
            ),
            "remaining_vulnerabilities": sorted(
                set(scan_before["vulnerability_ids"]) & set(scan_after["vulnerability_ids"])
            ),
        },
        "task4_vs_bom_before": compare_inventory_and_bom(inv_before, bom_before),
        "task4_vs_bom_after": compare_inventory_and_bom(inv_after, bom_after),
    }

    RESULT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with RESULT_PATH.open("w", encoding="utf-8") as file:
        json.dump(result, file, ensure_ascii=False, indent=2)

    print(f"Result file: {RESULT_PATH}")
    print()
    print("Inventory packages:")
    print(f"  records before:       {result['inventory_comparison']['before_record_count']}")
    print(f"  records after:        {result['inventory_comparison']['after_record_count']}")
    print(f"  unique names before:  {result['inventory_comparison']['before_unique_name_count']}")
    print(f"  unique names after:   {result['inventory_comparison']['after_unique_name_count']}")
    print(f"  added records:        {result['inventory_comparison']['added_record_count']}")
    print(f"  removed records:      {result['inventory_comparison']['removed_record_count']}")
    print(f"  added unique names:   {result['inventory_comparison']['added_unique_name_count']}")
    print(f"  changed versions:     {result['inventory_comparison']['changed_version_count']}")
    print()
    print("BOM components:")
    print(f"  records before:       {result['bom_comparison']['before_record_count']}")
    print(f"  records after:        {result['bom_comparison']['after_record_count']}")
    print(f"  changed versions:     {result['bom_comparison']['changed_version_count']}")
    print()
    print("OSV vulnerabilities:")
    print(f"  before: {result['osv_scan_comparison']['before']['vulnerability_count']}")
    print(f"  after:  {result['osv_scan_comparison']['after']['vulnerability_count']}")
    print()
    print("Task4 vs BOM:")
    print(f"  before only by name: {result['task4_vs_bom_before']['only_in_inventory_by_name_count']} / {result['task4_vs_bom_before']['only_in_bom_by_name_count']}")
    print(f"  after only by name:  {result['task4_vs_bom_after']['only_in_inventory_by_name_count']} / {result['task4_vs_bom_after']['only_in_bom_by_name_count']}")


if __name__ == "__main__":
    main()
