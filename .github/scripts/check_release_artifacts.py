#!/usr/bin/env python3
"""Check the agentvault-mls release artifacts before they can be published.

Usage:
    check_release_artifacts.py DIR [--expect-version X.Y.Z]

DIR holds the three wheels and the sdist built by release.yml. The script
exits non-zero, listing every problem, if any of these fail:

* exactly one wheel for each platform tag set that v0.1.1 shipped, and
  nothing else;
* every artifact is the agentvault-mls distribution (renamed from
  agentvault-mls-rs-uniffi in 0.1.2);
* every wheel carries a non-empty CycloneDX SBOM with none of the crates
  in FORBIDDEN. .cargo/audit.toml ignores RUSTSEC-2026-0387 on the grounds
  that the wheel does not contain crypto-bigint; this is what enforces
  that, and an empty or missing SBOM fails rather than passing vacuously;
* with --expect-version, every artifact's METADATA / PKG-INFO Version
  equals it. release.yml passes the tag minus its leading "v", so pushing
  v0.1.2 while pyproject.toml still says 0.1.1 cannot publish 0.1.1.

Only the standard library is used so it runs on a bare runner.
"""

import argparse
import email.parser
import json
import os
import sys
import tarfile
import zipfile

NAME = "agentvault-mls"
FILE_PREFIX = "agentvault_mls"

EXPECTED_TAG_SETS = [
    {"py3-none-manylinux_2_17_x86_64", "py3-none-manylinux2014_x86_64"},
    {
        "py3-none-macosx_10_12_x86_64",
        "py3-none-macosx_11_0_arm64",
        "py3-none-macosx_10_12_universal2",
    },
    {"py3-none-win_amd64"},
]

FORBIDDEN = {"crypto-bigint", "rusqlite", "libsqlite3-sys"}


def parse_metadata(raw):
    return email.parser.Parser().parsestr(raw.decode("utf-8"), headersonly=True)


def walk(components):
    for component in components:
        yield component
        yield from walk(component.get("components", []))


def check_wheel(path, expect_version, errors):
    base = os.path.basename(path)
    parts = base[: -len(".whl")].split("-")
    if len(parts) != 5:
        errors.append(f"{base}: not a wheel filename")
        return None
    dist, file_version, py, abi, plat = parts
    if dist != FILE_PREFIX:
        errors.append(f"{base}: distribution {dist!r}, expected {FILE_PREFIX!r}")
    tags = {f"{p}-{a}-{q}" for p in py.split(".") for a in abi.split(".") for q in plat.split(".")}

    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        metas = [n for n in names if n.count("/") == 1 and n.endswith(".dist-info/METADATA")]
        if len(metas) != 1:
            errors.append(f"{base}: expected one .dist-info/METADATA, found {len(metas)}")
            return tags
        dist_info = metas[0].split("/")[0]
        meta = parse_metadata(zf.read(metas[0]))
        if meta["Name"] != NAME:
            errors.append(f"{base}: METADATA Name {meta['Name']!r}, expected {NAME!r}")
        if meta["Version"] != file_version:
            errors.append(f"{base}: METADATA Version {meta['Version']!r} != filename {file_version!r}")
        if expect_version is not None and meta["Version"] != expect_version:
            errors.append(
                f"{base}: METADATA Version {meta['Version']!r}, expected {expect_version!r} from the tag"
            )

        sboms = [
            n for n in names
            if n.startswith(f"{dist_info}/sboms/") and n.endswith(".cyclonedx.json")
        ]
        if not sboms:
            errors.append(f"{base}: no {dist_info}/sboms/*.cyclonedx.json")
        total = 0
        for sbom in sboms:
            try:
                bom = json.loads(zf.read(sbom))
            except ValueError as exc:
                errors.append(f"{base}: {sbom} is not JSON: {exc}")
                continue
            components = list(walk(bom.get("components", [])))
            total += len(components)
            bad = sorted({c.get("name") for c in components} & FORBIDDEN)
            if bad:
                errors.append(f"{base}: {sbom} lists forbidden crates {bad}")
        if sboms and total == 0:
            errors.append(f"{base}: SBOM lists no components")
        print(f"{base}: Name={meta['Name']} Version={meta['Version']} "
              f"sbom_components={total}")
    return tags


def check_sdist(path, expect_version, errors):
    base = os.path.basename(path)
    if not base.startswith(f"{FILE_PREFIX}-"):
        errors.append(f"{base}: sdist not named {FILE_PREFIX}-<version>.tar.gz")
    file_version = base[len(FILE_PREFIX) + 1 : -len(".tar.gz")]
    with tarfile.open(path) as tf:
        member = f"{FILE_PREFIX}-{file_version}/PKG-INFO"
        try:
            meta = parse_metadata(tf.extractfile(member).read())
        except KeyError:
            errors.append(f"{base}: no {member}")
            return
    if meta["Name"] != NAME:
        errors.append(f"{base}: PKG-INFO Name {meta['Name']!r}, expected {NAME!r}")
    if meta["Version"] != file_version:
        errors.append(f"{base}: PKG-INFO Version {meta['Version']!r} != filename {file_version!r}")
    if expect_version is not None and meta["Version"] != expect_version:
        errors.append(
            f"{base}: PKG-INFO Version {meta['Version']!r}, expected {expect_version!r} from the tag"
        )
    print(f"{base}: Name={meta['Name']} Version={meta['Version']}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("dir")
    parser.add_argument("--expect-version")
    args = parser.parse_args()
    if args.expect_version is not None and not args.expect_version:
        sys.exit("--expect-version is empty")

    errors = []
    wheel_tag_sets = []
    sdists = 0
    for name in sorted(os.listdir(args.dir)):
        path = os.path.join(args.dir, name)
        if name.endswith(".whl"):
            wheel_tag_sets.append(check_wheel(path, args.expect_version, errors))
        elif name.endswith(".tar.gz"):
            sdists += 1
            check_sdist(path, args.expect_version, errors)
        else:
            errors.append(f"{name}: unexpected file")

    for tags in EXPECTED_TAG_SETS:
        n = sum(1 for found in wheel_tag_sets if found == tags)
        if n != 1:
            errors.append(f"expected one wheel tagged {sorted(tags)}, found {n}")
    if len(wheel_tag_sets) != len(EXPECTED_TAG_SETS):
        errors.append(f"expected {len(EXPECTED_TAG_SETS)} wheels, found {len(wheel_tag_sets)}")
    if sdists != 1:
        errors.append(f"expected one sdist, found {sdists}")

    if errors:
        for err in errors:
            print(f"::error::{err}")
        sys.exit(1)
    print("release artifacts OK"
          + (f" (version {args.expect_version})" if args.expect_version else ""))


if __name__ == "__main__":
    main()
