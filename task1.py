import json
from pathlib import Path
from importlib import metadata

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


OUTPUT_PATH = Path("results/result_task_1.json")


def make_pypi_url(name: str, version: str) -> str:
    if version:
        return f"https://pypi.org/project/{name}/{version}/"
    return f"https://pypi.org/project/{name}/"


def make_purl(name: str, version: str) -> str:
    normalized_name = canonicalize_name(name)
    if version:
        return f"pkg:pypi/{normalized_name}@{version}"
    return f"pkg:pypi/{normalized_name}"


def is_runtime_dependency(req: Requirement) -> bool:
    """
    Оставляем только основные runtime-зависимости.
    Optional extras вроде dotenv/async не включаем.
    """
    if req.marker is None:
        return True

    try:
        return req.marker.evaluate({"extra": ""})
    except Exception:
        return True


def main() -> None:
    try:
        flask_dist = metadata.distribution("Flask")
    except metadata.PackageNotFoundError:
        raise SystemExit(
            "Flask не установлен в текущем окружении. "
            "Сначала установи его командой: python3 -m pip install ./source/flask"
        )

    dependencies = []

    for raw_req in flask_dist.requires or []:
        req = Requirement(raw_req)

        if not is_runtime_dependency(req):
            continue

        name = req.name

        try:
            version = metadata.version(name)
        except metadata.PackageNotFoundError:
            version = ""

        dependencies.append({
            "name": name,
            "version": version,
            "ecosystem": "pypi",
            "url": make_pypi_url(name, version),
            "purl": make_purl(name, version)
        })

    dependencies = sorted(dependencies, key=lambda item: item["name"].lower())

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_PATH.open("w", encoding="utf-8") as file:
        json.dump(dependencies, file, ensure_ascii=False, indent=2)

    print(f"Result file: {OUTPUT_PATH}")
    print(f"Total dependencies: {len(dependencies)}")
    print("Ecosystem: pypi")

    for dep in dependencies:
        print(f"- {dep['name']} {dep['version']} | {dep['purl']}")


if __name__ == "__main__":
    main()
