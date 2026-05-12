#!/usr/bin/env python3
"""
OpenZeppelin Dependency Integrity Verifier

Verifies that vendored/copied @openzeppelin contract files match officially
published versions from the npm registry. Checks against both
@openzeppelin/contracts and @openzeppelin/contracts-upgradeable simultaneously.

Usage:
    python3 oz_integrity_verify.py ./my_vendored_oz
"""

import argparse
import concurrent.futures
import hashlib
import json
import os
import sys
import tarfile
import tempfile
import time
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import quote

NPM_REGISTRY = "https://registry.npmjs.org"
CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "openzeppelin_all_history_tarball")
TARGET_PACKAGES = ["@openzeppelin/contracts", "@openzeppelin/contracts-upgradeable"]

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


@dataclass
class HashHit:
    package_name: str
    official_path: str
    version: str


@dataclass
class FileResult:
    local_path: str
    local_sha256: str
    hits: list[HashHit]

    @property
    def is_verified(self) -> bool:
        return len(self.hits) > 0


@dataclass
class VerifyReport:
    target_dir: str
    total_files: int
    verified: int
    unmatched: list[FileResult]
    results: list[FileResult]
    package_stats: list[dict]
    fetch_errors: list[str] = field(default_factory=list)


def sha256_file(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch_all_versions(package_name: str) -> list[str]:
    url = f"{NPM_REGISTRY}/{quote(package_name, safe='@')}"
    try:
        resp = urllib.request.urlopen(url, timeout=30)
        data = json.loads(resp.read())
        return sorted(data.get("versions", {}).keys())
    except Exception as e:
        print(f"  {RED}Failed to fetch versions for {package_name}: {e}{RESET}")
        return []


def _cache_dir(package_name: str) -> str:
    safe_name = package_name.replace("/", "_").replace("@", "")
    path = os.path.join(CACHE_DIR, safe_name)
    os.makedirs(path, exist_ok=True)
    return path


def download_tarball(package_name: str, version: str, use_cache: bool = True) -> Optional[str]:
    pkg_cache = _cache_dir(package_name)
    tgz_path = os.path.join(pkg_cache, f"v{version}.tgz")
    if use_cache and os.path.isfile(tgz_path):
        return tgz_path
    pkg_basename = package_name.split("/", 1)[1]
    url = f"{NPM_REGISTRY}/{package_name}/-/{pkg_basename}-{version}.tgz"
    try:
        urllib.request.urlretrieve(url, tgz_path)
        return tgz_path
    except Exception:
        if os.path.isfile(tgz_path):
            os.remove(tgz_path)
        raise


def hash_tarball_sol_files(tgz_path: str) -> dict[str, str]:
    """Returns {relative_path: sha256} for all .sol files inside the tarball."""
    result = {}
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            with tarfile.open(tgz_path, "r:gz") as tar:
                tar.extractall(tmpdir)
        except Exception:
            return result
        root = os.path.join(tmpdir, "package")
        if not os.path.isdir(root):
            items = [d for d in os.listdir(tmpdir) if os.path.isdir(os.path.join(tmpdir, d))]
            root = os.path.join(tmpdir, items[0]) if items else tmpdir
        for dirpath, _, filenames in os.walk(root):
            for fname in filenames:
                if fname.endswith(".sol"):
                    full = os.path.join(dirpath, fname)
                    result[os.path.relpath(full, root)] = sha256_file(full)
    return result


def build_hash_index(
    max_versions: Optional[int] = None,
    use_cache: bool = True,
    max_workers: int = 8,
) -> tuple[dict[str, list[HashHit]], list[str]]:
    """Build unified SHA256 → [HashHit, ...] index across all TARGET_PACKAGES."""
    all_work: list[tuple[str, str]] = []
    for pkg_name in TARGET_PACKAGES:
        versions = fetch_all_versions(pkg_name)
        if max_versions and max_versions < len(versions):
            versions = versions[-max_versions:]
        all_work.extend((pkg_name, v) for v in versions)

    total = len(all_work)
    index: dict[str, list[HashHit]] = defaultdict(list)
    cached_count = 0
    fetch_errors: list[str] = []
    completed = 0

    def _fetch(pkg_name: str, version: str):
        nonlocal cached_count
        try:
            tgz = download_tarball(pkg_name, version, use_cache=use_cache)
            return pkg_name, version, hash_tarball_sol_files(tgz)
        except Exception as e:
            fetch_errors.append(f"[{pkg_name}] v{version}: {e}")
            return pkg_name, version, {}

    print(f"  Building hash index over {total} versions across {len(TARGET_PACKAGES)} packages...\n")

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_fetch, pkg, v): (pkg, v) for pkg, v in all_work}
        for future in concurrent.futures.as_completed(futures):
            completed += 1
            pkg_name, version, file_hashes = future.result()
            for relpath, sha in file_hashes.items():
                index[sha].append(HashHit(
                    package_name=pkg_name, official_path=relpath, version=version,
                ))
            if completed % 20 == 0 or completed == total:
                pct = completed * 100 // total
                bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
                print(
                    f"\r  {CYAN}[{bar}]{RESET} {completed}/{total} versions processed "
                    f"({len(index)} unique hashes indexed)",
                    end="", flush=True,
                )
    print()
    return dict(index), fetch_errors


def normalize_path(filepath: str, target_dir: str) -> str:
    """Strip vendoring prefixes so local paths match tarball structure."""
    rel = os.path.relpath(filepath, target_dir)
    for prefix in ("@openzeppelin/contracts-upgradeable/", "@openzeppelin/contracts/"):
        if rel.startswith(prefix):
            return rel[len(prefix):]
    return rel


def verify(target_dir: str, max_versions: Optional[int] = None, use_cache: bool = True, max_workers: int = 8) -> VerifyReport:
    print(f"{BOLD}OpenZeppelin Integrity Verifier{RESET}\n")
    print(f"  Target: {target_dir}")

    # 1. Hash local .sol files
    print(f"  {CYAN}Step 1/3: Hashing local files...{RESET}")
    local: dict[str, tuple[str, str]] = {}
    for dirpath, _, filenames in os.walk(target_dir):
        for fname in filenames:
            if not fname.endswith(".sol"):
                continue
            full = os.path.join(dirpath, fname)
            sha = sha256_file(full)
            norm = normalize_path(full, target_dir)
            if norm not in local or len(full) > len(local[norm][0]):
                local[norm] = (full, sha)

    print(f"  Found {len(local)} .sol files to verify\n")
    if not local:
        print(f"  {YELLOW}No .sol files found.{RESET}")
        return VerifyReport(target_dir=target_dir, total_files=0, verified=0, unmatched=[], results=[], package_stats=[])

    # 2. Build hash index
    print(f"  {CYAN}Step 2/3: Building hash index from npm...{RESET}")
    start = time.time()
    index, fetch_errors = build_hash_index(
        max_versions=max_versions, use_cache=use_cache, max_workers=max_workers,
    )
    print(f"  Index built in {time.time() - start:.1f}s\n")
    if not index:
        print(f"  {RED}Failed to build index. Aborting.{RESET}")
        return VerifyReport(target_dir=target_dir, total_files=len(local), verified=0,
                            unmatched=[], results=[], package_stats=[], fetch_errors=fetch_errors)

    # 3. Match
    print(f"  {CYAN}Step 3/3: Matching...{RESET}\n")
    results: list[FileResult] = []
    unmatched: list[FileResult] = []
    # pkg → {version → {files}}
    pkg_vs: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))

    for norm, (_, sha) in sorted(local.items()):
        hits = index.get(sha, [])
        fr = FileResult(local_path=norm, local_sha256=sha, hits=hits)
        if hits:
            results.append(fr)
            for h in hits:
                pkg_vs[h.package_name][h.version].add(norm)
        else:
            unmatched.append(fr)

        short = norm if len(norm) < 55 else "..." + norm[-52:]
        if hits:
            by_pkg: dict[str, list[str]] = defaultdict(list)
            for h in hits:
                by_pkg[h.package_name].append(h.version)
            parts = []
            for pkg in sorted(by_pkg):
                vers = sorted(set(by_pkg[pkg]))
                vs = ", ".join(vers[:3])
                if len(vers) > 3:
                    vs += f" (+{len(vers) - 3} more)"
                parts.append(f"{pkg}@{vs}")
            print(f"  {GREEN}✓{RESET} {short}")
            print(f"     {CYAN}→ {', '.join(parts)}{RESET}")
        else:
            print(f"  {RED}✗{RESET} {norm}")
            print(f"     {RED}→ NO match in any historical version!{RESET}")

    print()

    # Package stats
    package_stats: list[dict] = []
    for pkg_name in TARGET_PACKAGES:
        vm = pkg_vs.get(pkg_name, {})
        best_v, best_n = None, 0
        for v, paths in vm.items():
            if len(paths) > best_n:
                best_n, best_v = len(paths), v
        pct = best_n * 100 // len(local) if best_v else 0
        bar = "█" * (pct // 10) + "░" * (10 - pct // 10)
        if best_v:
            print(f"  {BOLD}{pkg_name}{RESET}  best: {CYAN}v{best_v}{RESET}  [{bar}] {best_n}/{len(local)} ({pct}%)")
        else:
            print(f"  {BOLD}{pkg_name}{RESET}  {YELLOW}no matches{RESET}")
        package_stats.append({
            "package": pkg_name, "matched": len(set().union(*vm.values())),
            "best_version": best_v, "best_count": best_n,
        })

    print()
    v = len(results)
    if v == len(local):
        print(f"  {GREEN}{BOLD}ALL {v}/{len(local)} FILES VERIFIED{RESET} — no tampering detected.")
    else:
        print(f"  {RED}{BOLD}WARNING: {len(unmatched)}/{len(local)} files unverified!{RESET}")

    if fetch_errors:
        print(f"\n  {YELLOW}Note: {len(fetch_errors)} tarball(s) could not be fetched.{RESET}")
    print(f"\n  {BOLD}Cache:{RESET} {CACHE_DIR}")

    return VerifyReport(
        target_dir=target_dir, total_files=len(local), verified=v,
        unmatched=unmatched, results=results, package_stats=package_stats,
        fetch_errors=fetch_errors,
    )


def main():
    parser = argparse.ArgumentParser(
        description="Verify vendored @openzeppelin contracts against npm releases",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n  python3 oz_verify.py ./my_vendored_oz\n  python3 oz_verify.py ./my_dir --versions 20",
    )
    parser.add_argument("target_dir", help="Directory containing vendored OZ .sol files")
    parser.add_argument("--versions", type=int, default=0, metavar="N",
                        help="Only check latest N versions per package (0 = all)")
    parser.add_argument("--no-cache", action="store_true", help="Skip disk cache")
    parser.add_argument("--workers", type=int, default=8, metavar="N",
                        help="Concurrent downloads (default: 8)")
    args = parser.parse_args()

    target_dir = os.path.abspath(args.target_dir)
    if not os.path.isdir(target_dir):
        print(f"{RED}Error: '{args.target_dir}' is not a directory{RESET}")
        sys.exit(1)

    report = verify(
        target_dir=target_dir,
        max_versions=args.versions if args.versions > 0 else None,
        use_cache=not args.no_cache,
        max_workers=args.workers,
    )

    if report.fetch_errors and report.unmatched:
        sys.exit(2)
    if report.unmatched:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
