"""Fails when a crate is released without a breaking version bump although a crate in its public API had one.

release-plz bumps a crate according to the commits that touched its files, and cargo-semver-checks compares API
shapes. Neither notices that a crate's public API changes when a dependency whose types it exposes gets a breaking
update (identity-kit 0.2 -> 0.3, or `oid4vc-core` 0.2 -> 0.3 for the crates using its types). See docs/RELEASE.md.

For every publishable workspace crate whose version differs from its last tag (`<crate>-v<version>`), this script
compares the versions `Cargo.lock` resolves its public dependencies to at that tag and now, and reports the crate if
one of them changed incompatibly while the crate's own version change is compatible. The public dependencies are the
crate's normal dependencies that are workspace crates or listed in `PUBLIC_DEPENDENCIES`; a crate that only uses one
of them internally is reported too, which before 1.0 costs no more than an unneeded minor bump.

Run from the workspace root, with the tags fetched: `python3 .github/scripts/check_public_dependency_bumps.py`.
"""

import json
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

# External crates whose types or traits appear in the public API of the workspace crates (taken once from rustdoc's
# JSON output, plus `serde` for the `Serialize` bounds).
PUBLIC_DEPENDENCIES = {
    "anyhow",
    "axum",
    "ed25519-dalek",
    "http",
    "identity-kit",
    "jsonwebtoken",
    "monostate",
    "reqwest",
    "reqwest-middleware",
    "serde",
    "serde_json",
    "tokio",
    "url",
    "utoipa",
}


def run(*args: str) -> str:
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


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


def resolved_dependencies(lockfile: str, crate: str, version: str) -> dict[str, str]:
    """The versions `Cargo.lock` resolves the crate's dependencies to, by package name."""
    packages = tomllib.loads(lockfile)["package"]
    entry = next(package for package in packages if package["name"] == crate and package["version"] == version)
    resolved = {}
    for dependency in entry.get("dependencies", []):
        # An entry is `name` when the lockfile has one version of the crate, `name version` otherwise.
        name, _, dependency_version = dependency.partition(" ")
        resolved[name] = dependency_version or next(p["version"] for p in packages if p["name"] == name)
    return resolved


def main() -> int:
    metadata = json.loads(run("cargo", "metadata", "--format-version", "1", "--no-deps", "--locked"))
    workspace_crates = {package["name"] for package in metadata["packages"]}
    current_lockfile = Path("Cargo.lock").read_text()

    # The crates being released: name -> (last released version, new version, public dependencies' versions).
    releases = {}
    for package in metadata["packages"]:
        # `publish = false` is an empty list of registries.
        if package["publish"] == []:
            continue
        crate, version = package["name"], package["version"]
        tags = run("git", "tag", "--list", f"{crate}-v*").split()
        released = max((tag.removeprefix(f"{crate}-v") for tag in tags), key=parse_version, default=None)
        if released is None or released == version:
            continue
        public = {
            dependency["name"]
            for dependency in package["dependencies"]
            if dependency["kind"] is None
            and (dependency["name"] in workspace_crates or dependency["name"] in PUBLIC_DEPENDENCIES)
        }
        before = resolved_dependencies(run("git", "show", f"{crate}-v{released}:Cargo.lock"), crate, released)
        after = resolved_dependencies(current_lockfile, crate, version)
        versions = {name: (before[name], after[name]) for name in public & before.keys() & after.keys()}
        releases[crate] = (released, version, versions)

    # A crate needs a breaking release when a public dependency has an incompatible update, or is a workspace crate
    # that needs a breaking release itself. Repeat until no crate is added.
    reasons: dict[str, str] = {}
    changed = True
    while changed:
        changed = False
        for crate, (_, _, versions) in releases.items():
            if crate in reasons:
                continue
            for name, (old, new) in sorted(versions.items()):
                if not compatible(old, new):
                    reasons[crate] = f"`{name}`, which goes from {old} to {new}"
                elif name in reasons:
                    reasons[crate] = f"`{name}`, which needs a breaking release itself"
                else:
                    continue
                changed = True
                break

    problems = [
        f"{crate} {releases[crate][0]} -> {releases[crate][1]}: it depends on {reason}. Release {crate} with a "
        'breaking version (docs/RELEASE.md, "Public dependencies").'
        for crate, reason in sorted(reasons.items())
        if compatible(releases[crate][0], releases[crate][1])
    ]
    for problem in problems:
        print(f"::error::{problem}" if os.environ.get("GITHUB_ACTIONS") else problem)
    if not problems:
        print("Every crate with an incompatible update of a public dependency gets a breaking release.")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
