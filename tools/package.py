#!/usr/bin/env python3
"""Package a dataset's full logs as release assets.

    python3 tools/package.py datasets/apache-shopfront/2026-08-16-small

The repository carries the manifest, the READMEs and a 5,000-line sample. The
full logs are too large to commit and are published as release assets instead;
this is what builds them, and it is the last step before a release.

**Regeneration is still the primary distribution channel.** Anyone with this
repository runs `tools/build.py` and gets the dataset. Release assets are a
convenience for people who want the exact bytes without a Docker daemon.

`SHA256SUMS` covers **both** the archives and their uncompressed contents, and
the committed files as well. A checksum over an archive proves the download
arrived intact. A checksum over the contents proves the dataset is the one the
manifest describes -- which is the question a consumer actually has, and it
survives the file being recompressed with different settings or a different
tool.

xz rather than zstd: `lzma` is in the standard library, so packaging needs
nothing installed, and this project's host entry points are stdlib-only by
rule. Logs compress extremely well either way.

Standard library only.
"""

import argparse
import hashlib
import lzma
import sys
from pathlib import Path
from typing import NamedTuple

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

SUMS_NAME = "SHA256SUMS"

#: Compressed and published. Ordered so a release listing always reads the
#: same way, and so the file a consumer most likely wants is first.
ASSETS = (
    "access.log",
    "truth.jsonl",
    "access.raw.log",
    "truth.raw.jsonl",
    "access.apache.log",
    "access.tagged.log",
    "error.log",
)

#: Committed to the repository, so not compressed -- but still checksummed, so
#: a downloaded release can be verified without a git checkout.
COMMITTED = ("MANIFEST.json", "README.md", "sample.log", "sample.truth.jsonl")

#: Without this the directory is not a dataset, whatever else is in it.
REQUIRED = ("MANIFEST.json", "access.log")

_CHUNK = 1 << 20


class PackageReport(NamedTuple):
    dataset: Path
    archives: tuple
    original_bytes: int
    compressed_bytes: int
    sums_path: Path

    @property
    def ratio(self):
        if not self.original_bytes:
            return 0.0
        return round(self.compressed_bytes / self.original_bytes, 4)


def assets_for(dataset):
    """The files in this dataset that get compressed and published.

    Absent ones are skipped rather than being an error: a dataset built
    without the timestamp remap has no `access.raw.log`, and that is a fact
    about the dataset rather than a fault in it.
    """
    dataset = Path(dataset)
    return [dataset / name for name in ASSETS if (dataset / name).is_file()]


def _digest(path):
    sha = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(_CHUNK), b""):
            sha.update(block)
    return sha.hexdigest()


def _compress(source, target):
    """Stream it. A medium-tier log does not want to be held in memory twice
    just to be compressed."""
    with open(source, "rb") as raw, lzma.open(target, "wb", preset=6) as out:
        for block in iter(lambda: raw.read(_CHUNK), b""):
            out.write(block)


def package(dataset, out_dir=None):
    dataset = Path(dataset)
    out_dir = Path(out_dir) if out_dir else dataset

    missing = [name for name in REQUIRED if not (dataset / name).is_file()]
    if missing:
        raise ValueError(
            f"{dataset} is not a finished dataset: missing "
            f"{', '.join(missing)}. Run tools/build.py first, and "
            f"tools/verify.py after it.")

    archives, original, compressed = [], 0, 0
    for source in assets_for(dataset):
        target = out_dir / f"{source.name}.xz"
        _compress(source, target)
        archives.append(target)
        original += source.stat().st_size
        compressed += target.stat().st_size

    # Contents first, then archives, then what the repository carries. A
    # consumer checking after decompression reads the top of the file.
    lines = ["# Contents, after decompression. These are the bytes the build",
             "# produced and the manifest describes.",
             ""]
    for source in assets_for(dataset):
        lines.append(f"{_digest(source)}  {source.name}")

    lines += ["", "# Archives, as downloaded.", ""]
    for archive in archives:
        lines.append(f"{_digest(archive)}  {archive.name}")

    present = [name for name in COMMITTED if (dataset / name).is_file()]
    if present:
        lines += ["", "# Also in the repository, checksummed so a release can",
                  "# be verified without a git checkout.", ""]
        for name in present:
            lines.append(f"{_digest(dataset / name)}  {name}")

    sums_path = out_dir / SUMS_NAME
    sums_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    return PackageReport(dataset=dataset, archives=tuple(archives),
                         original_bytes=original, compressed_bytes=compressed,
                         sums_path=sums_path)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset")
    parser.add_argument("--out", default=None,
                        help="where to write the archives (default: beside "
                             "the dataset)")
    args = parser.parse_args(argv)

    try:
        report = package(args.dataset, args.out)
    except ValueError as exc:
        print(f"package failed: {exc}", file=sys.stderr)
        return 1

    print(f"\n=== {report.dataset.name} ===")
    for archive in report.archives:
        print(f"  {archive.name:<28} {archive.stat().st_size / 1e6:>9.2f} MB")
    print(f"\n  {report.original_bytes / 1e6:.1f} MB -> "
          f"{report.compressed_bytes / 1e6:.1f} MB "
          f"({report.ratio:.1%} of the original)")
    print(f"  {report.sums_path.name} covers contents, archives and the "
          f"committed files")
    print("\nVerify a download with:")
    print(f"  sha256sum -c {SUMS_NAME} --ignore-missing")
    return 0


if __name__ == "__main__":
    sys.exit(main())
