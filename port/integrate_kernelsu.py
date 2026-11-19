#!/usr/bin/env python3
"""Materialize and verify KernelSU Next from the committed source lock."""

import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile

HERE = Path(__file__).resolve().parent
UPSTREAM = "https://github.com/KernelSU-Next/KernelSU-Next.git"
SUSFS_UPSTREAM = "https://github.com/pershoot/KernelSU-Next.git"
COMMON_REVISION = json.loads((HERE / "sources.json").read_text())["common"]["revision"]


def validate_pin(pin):
    fields = {"repository", "branch", "revision", "tag", "git_commit_count", "version", "sha256"}
    builtin = isinstance(pin, dict) and pin.get("repository") == SUSFS_UPSTREAM
    if builtin:
        fields.add("upstream_revision")
    if (not isinstance(pin, dict) or set(pin) != fields
            or (pin.get("repository"), pin.get("branch")) not in {
                (UPSTREAM, "dev"), (SUSFS_UPSTREAM, "dev-susfs")}
            or not isinstance(pin.get("revision"), str)
            or not re.fullmatch(r"[0-9a-f]{40}", pin.get("revision", ""))
            or (builtin and (not isinstance(pin.get("upstream_revision"), str)
                or not re.fullmatch(r"[0-9a-f]{40}", pin["upstream_revision"])))
            or not isinstance(pin.get("sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", pin.get("sha256", ""))
            or type(pin.get("git_commit_count")) is not int
            or pin["git_commit_count"] < 1
            or pin.get("version") != 30000 + pin["git_commit_count"]
            or not isinstance(pin.get("tag"), str)
            or not re.fullmatch(r"[A-Za-z0-9._+-]+", pin.get("tag", ""))):
        raise ValueError("invalid KernelSU Next source lock")
    return pin


def verify_repository_pin(repo, pin):
    """Bind fork version metadata to the included official dev commit."""
    validate_pin(pin)
    revision = pin["revision"]
    base = pin.get("upstream_revision", revision)
    if subprocess.run(["git", "-C", str(repo), "merge-base", "--is-ancestor", base, revision],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
        raise ValueError("KernelSU Next fork does not include its locked official dev revision")
    count = int(subprocess.check_output([
        "git", "-C", str(repo), "rev-list", "--count", base], text=True).strip())
    tag = subprocess.check_output([
        "git", "-C", str(repo), "describe", "--tags", "--abbrev=0", base], text=True).strip()
    if count != pin["git_commit_count"] or tag != pin["tag"]:
        raise ValueError("KernelSU Next version metadata differs from the locked official dev base")


def locked_pin():
    return validate_pin(json.loads((HERE / "kernelsu-lock.json").read_text()))


def expected(common, require_lock=True):
    source = common.parent / ".kernelsu-next"
    pin = validate_pin(json.loads((source / "source.json").read_text()))
    if require_lock and pin != locked_pin():
        raise ValueError("KernelSU Next inputs differ from the committed source lock")
    data = (source / "source.tar").read_bytes()
    if hashlib.sha256(data).hexdigest() != pin["sha256"]:
        raise ValueError("KernelSU Next source archive hash mismatch")
    files = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        for entry in archive:
            if not entry.isfile():
                continue
            path = Path(entry.name)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError("unsafe KernelSU Next archive path")
            if path.parts[0] == "uapi":
                # Upstream kernel/include/uapi is a symlink to ../../uapi.
                # Materialize its target so Kleaf's source glob sees the headers.
                target = Path("drivers/kernelsu/include") / path
            else:
                target = Path("drivers/kernelsu") / (path.relative_to("kernel")
                         if path.parts[0] == "kernel" else path)
            files[target.as_posix()] = archive.extractfile(entry).read()
    kbuild = files["drivers/kernelsu/Kbuild"].decode()
    start = kbuild.index("LPATH :=")
    end = kbuild.index("KSU_NEW_DCACHE_FLUSH :=")
    # Resolve Git metadata before entering Kleaf's hermetic build sandbox.
    # Fork commits do not change the official Manager-facing version and tag.
    upstream_revision = pin.get("upstream_revision", pin["revision"])
    description = (f"# Pinned {pin['branch']} {pin['revision']}; official dev {upstream_revision}.\n"
                   if "upstream_revision" in pin else
                   f"# Upstream dev {pin['revision']}; see artifact inputs/kernelsu-next.\n")
    kbuild = (kbuild[:start] + description
              + f"ccflags-y += -DKSU_VERSION={pin['version']}\n"
              + 'ccflags-y += -DKSU_VERSION_TAG=\\"' + pin['tag'] + '\\"\n\n'
              + kbuild[end:])
    files["drivers/kernelsu/Kbuild"] = kbuild.encode()
    additions = {
        "drivers/Makefile": '\nobj-$(CONFIG_KSU) += kernelsu/\n',
        "drivers/Kconfig": '\nsource "drivers/kernelsu/Kconfig"\n',
    }
    for name, addition in additions.items():
        original = subprocess.check_output([
            "git", "-C", str(common), "show", f"{COMMON_REVISION}:{name}"])
        files[name] = original + addition.encode()
    return files, additions


def verify(common, require_lock=True):
    if (common / "drivers/kernelsu").is_symlink():
        raise ValueError("unexpected KernelSU Next source symlink")
    files, additions = expected(common, require_lock)
    changed = subprocess.check_output([
        "git", "-C", str(common), "diff", "HEAD", "--name-only"], text=True).splitlines()
    if set(changed) != set(additions):
        raise ValueError("unexpected tracked changes in common")
    actual = {p.relative_to(common).as_posix() for p in
              (common / "drivers/kernelsu").rglob("*") if p.is_file()}
    wanted = {p for p in files if p.startswith("drivers/kernelsu/")}
    if actual != wanted:
        raise ValueError("KernelSU Next source file set mismatch")
    for name, contents in files.items():
        path = common / name
        if path.is_symlink() or path.read_bytes() != contents:
            raise ValueError(f"KernelSU Next integration differs: {name}")
    return files


def integrate(common):
    previous = None
    if (common / "drivers/kernelsu").exists():
        previous = verify(common, require_lock=False)
    elif subprocess.check_output([
            "git", "-C", str(common), "status", "--porcelain", "-uno"]):
        raise ValueError("preserve tracked common changes before integrating KernelSU Next")
    source = common.parent / ".kernelsu-next"
    repo = source / "repo"
    source.mkdir(exist_ok=True)
    pin = locked_pin()
    archive = source / "source.tar"
    data = archive.read_bytes() if archive.exists() else None
    if data is None or hashlib.sha256(data).hexdigest() != pin["sha256"]:
        if repo.exists():
            bare = subprocess.check_output([
                "git", "-C", str(repo), "rev-parse", "--is-bare-repository"], text=True).strip()
            if bare != "true" and subprocess.check_output([
                    "git", "-C", str(repo), "status", "--porcelain"]):
                raise ValueError("preserve local changes in the KernelSU Next checkout")
            remote = subprocess.check_output([
                "git", "-C", str(repo), "remote", "get-url", "origin"], text=True).strip()
            if remote != pin["repository"] and not (
                    pin["repository"] == SUSFS_UPSTREAM and remote == UPSTREAM):
                raise ValueError("unexpected KernelSU Next origin")
        else:
            subprocess.run(["git", "clone", "--bare", pin["repository"], str(repo)], check=True)
        revision = pin["revision"]
        available = subprocess.run(["git", "-C", str(repo), "cat-file", "-e", revision + "^{commit}"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if available.returncode:
            # An existing verified official checkout can supply the base objects without
            # changing its remote; the new immutable fork revision comes from its own URL.
            subprocess.run(["git", "-C", str(repo), "fetch", pin["repository"], revision], check=True)
        verify_repository_pin(repo, pin)
        data = subprocess.check_output([
            "git", "-C", str(repo), "archive", "--format=tar", revision, "kernel", "uapi", "LICENSE"])
        if hashlib.sha256(data).hexdigest() != pin["sha256"]:
            raise ValueError("fetched KernelSU Next archive differs from the source lock")
    # Refresh only a previously verified source tree. Unknown edits are never reset.
    if previous is not None:
        verify(common, require_lock=False)
        shutil.rmtree(common / "drivers/kernelsu")
    (source / "source.tar").write_bytes(data)
    (source / "source.json").write_text(json.dumps(pin, indent=2) + "\n")
    files, _ = expected(common)
    for name, contents in files.items():
        path = common / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents)
    verify(common)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workspace", type=Path)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    (verify if args.verify_only else integrate)(args.workspace.resolve() / "common")
    pin = json.loads((args.workspace / ".kernelsu-next/source.json").read_text())
    print(f"Pinned KernelSU Next {pin['revision']} / {pin['version']}: source and integration verified")
