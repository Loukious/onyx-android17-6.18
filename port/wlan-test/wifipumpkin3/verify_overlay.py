"""Read-only verification of the baseline and patched package files."""
import argparse
import hashlib
import json
from pathlib import Path


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--root", required=True, type=Path,
                    help="Directory containing the installed wifipumpkin3 package")
parser.add_argument("--state", choices=("before", "after"), required=True)
parser.add_argument("--manifest", type=Path, default=Path(__file__).with_name("preserve-upstream-v6.json"))
args = parser.parse_args()
manifest = json.loads(args.manifest.read_text())
errors = []
for entry in manifest["files"]:
    path = args.root / entry["path"]
    expected = entry[args.state + "_sha256"]
    if expected is None:
        if path.exists() or path.is_symlink():
            errors.append(str(path) + ": expected to be absent")
    elif not path.is_file() or path.is_symlink():
        errors.append(str(path) + ": missing file or unexpected symlink")
    elif hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        errors.append(str(path) + ": SHA256 does not match " + args.state)
if errors:
    raise SystemExit("\n".join(errors))
print("Verified {} package files in {} state".format(len(manifest["files"]), args.state))
