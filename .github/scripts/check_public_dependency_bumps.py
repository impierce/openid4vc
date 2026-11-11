"""Fails when a crate is released without a breaking version bump although a crate in its public API had one.

release-plz bumps a crate according to the commits that touched its files, and cargo-semver-checks compares API
shapes. Neither notices that a crate's public API changes when a dependency whose types it exposes gets a breaking
update (identity-kit 0.2 -> 0.3, or `oid4vc-core` 0.2 -> 0.3 for the crates using its types). See docs/RELEASE.md.

For every publishable workspace crate whose version differs from its last tag (`<crate>-v<version>`), this script
collects the crates whose items appear in its public API (from rustdoc's JSON output), compares their versions in
`Cargo.lock` at that tag and now, and reports the crate if one of them changed incompatibly while the crate's own
version change is compatible.

Run from the workspace root, with the tags fetched: `python3 .github/scripts/check_public_dependency_bumps.py`.
"""

import json
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

# Crates of the Rust distribution, which have no version in `Cargo.lock`.
TOOLCHAIN_CRATES = {"std", "core", "alloc", "proc_macro", "test"}


def run(*args: str, env: dict[str, str] | None = None) -> str:
    return subprocess.run(args, check=True, capture_output=True, text=True, env=env).stdout


def parse_version(version: str) -> tuple[int, int, int]:
    major, minor, patch = re.match(r"(\d+)\.(\d+)\.(\d+)", version).groups()
    return int(major), int(minor), int(patch)


def compatible(old: str, new: str) -> bool:
    """Whether Cargo treats `new` as a compatible update of `old` (`^old` matches `new`)."""
    old_parts, new_parts = parse_version(old), parse_version(new)
    if new_parts < old_parts:
        return False
    # The leftmost non-zero component is the one that must stay the same.
    significant = next((index for index, part in enumerate(old_parts) if part != 0), 2)
    return old_parts[: significant + 1] == new_parts[: significant + 1]


def last_release(crate: str) -> str | None:
    """The version of the crate's latest tag, or `None` if it was never released."""
    versions = [tag.removeprefix(f"{crate}-v") for tag in run("git", "tag", "--list", f"{crate}-v*").split()]
    return max(versions, key=parse_version, default=None)


def public_crates(crate: str, target_dir: Path) -> set[str]:
    """The crates whose types or traits appear in the crate's public API, with all features enabled."""
    # rustdoc's JSON output is unstable; `RUSTC_BOOTSTRAP` enables it on the stable toolchain, as cargo-semver-checks
    # does.
    env = {**os.environ, "RUSTC_BOOTSTRAP": "1", "CARGO_TARGET_DIR": str(target_dir)}
    run(
        "cargo",
        "rustdoc",
        "--quiet",
        "--locked",
        "--all-features",
        "--package",
        crate,
        "--",
        "-Zunstable-options",
        "--output-format",
        "json",
        env=env,
    )
    document = json.loads((target_dir / "doc" / f"{crate.replace('-', '_')}.json").read_text())
    paths, external_crates = document["paths"], document["external_crates"]

    found: set[str] = set()

    def collect(node: object) -> None:
        if isinstance(node, dict):
            path = node.get("resolved_path")
            if isinstance(path, dict):
                summary = paths.get(str(path.get("id")))
                if summary and summary["crate_id"] != 0:
                    found.add(external_crates[str(summary["crate_id"])]["name"])
            for value in node.values():
                collect(value)
        elif isinstance(node, list):
            for value in node:
                collect(value)

    for item in document["index"].values():
        if item["crate_id"] != 0:
            continue
        implementation = item["inner"].get("impl")
        # Auto trait and blanket implementations come from the compiler and `std`, not from the crate's API.
        if implementation and (implementation.get("is_synthetic") or implementation.get("blanket_impl")):
            continue
        collect(item["inner"])
    return found - TOOLCHAIN_CRATES


def resolved_dependencies(lockfile: str, crate: str, version: str) -> dict[str, str]:
    """The versions `Cargo.lock` resolves the crate's dependencies to, keyed by library name (`identity_kit`)."""
    packages = tomllib.loads(lockfile)["package"]
    versions_by_name: dict[str, list[str]] = {}
    for package in packages:
        versions_by_name.setdefault(package["name"], []).append(package["version"])
    entry = next(package for package in packages if package["name"] == crate and package["version"] == version)
    resolved = {}
    for dependency in entry.get("dependencies", []):
        # An entry is `name` when the lockfile has one version of the crate, `name version` otherwise.
        name, _, dependency_version = dependency.partition(" ")
        resolved[name.replace("-", "_")] = dependency_version or versions_by_name[name][0]
    return resolved


def main() -> int:
    metadata = json.loads(run("cargo", "metadata", "--format-version", "1", "--no-deps", "--locked"))
    target_dir = Path(metadata["target_directory"]) / "public-dependency-check"
    current_lockfile = Path("Cargo.lock").read_text()

    # The crates being released: name -> (last released version, new version, public crates, versions before, after).
    releases = {}
    for package in metadata["packages"]:
        # `publish = false` is an empty list of registries.
        if package["publish"] == []:
            continue
        crate, version = package["name"], package["version"]
        released = last_release(crate)
        if released is None or released == version:
            continue
        released_lockfile = run("git", "show", f"{crate}-v{released}:Cargo.lock")
        releases[crate.replace("-", "_")] = (
            released,
            version,
            public_crates(crate, target_dir),
            resolved_dependencies(released_lockfile, crate, released),
            resolved_dependencies(current_lockfile, crate, version),
        )

    # A crate needs a breaking release when a crate in its public API has an incompatible update, or needs a breaking
    # release itself (`oid4vc-core` for the crates using its types). Repeat until no crate is added.
    reasons: dict[str, str] = {}
    changed = True
    while changed:
        changed = False
        for crate, (released, version, public, before, after) in releases.items():
            if crate in reasons:
                continue
            for dependency in sorted(public & before.keys() & after.keys()):
                if not compatible(before[dependency], after[dependency]):
                    reasons[crate] = f"`{dependency}`, which goes from {before[dependency]} to {after[dependency]}"
                elif dependency in reasons:
                    reasons[crate] = f"`{dependency}`, which needs a breaking release itself"
                else:
                    continue
                changed = True
                break

    problems = []
    for crate, reason in sorted(reasons.items()):
        released, version = releases[crate][:2]
        if compatible(released, version):
            name = crate.replace("_", "-")
            problems.append(
                f"{name} {released} -> {version}: its public API uses {reason}. Release {name} with a breaking "
                'version (docs/RELEASE.md, "Public dependencies").'
            )

    for problem in problems:
        print(f"::error::{problem}" if os.environ.get("GITHUB_ACTIONS") else problem)
    if not problems:
        print("Every crate with an incompatible update of a crate in its public API gets a breaking release.")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
