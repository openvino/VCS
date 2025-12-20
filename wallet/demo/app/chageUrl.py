#!/usr/bin/env python3
"""
Usage:
  python scripts/update_endpoints.py \
    --old localhost \
    --new my-vm.example.com \
    --paths test/integration/fixtures/profile/profiles.json \
            test/integration/fixtures/docker-compose.yml \
            demo/app/lib/assets/config.json
"""

import argparse
from pathlib import Path

def replace_in_file(path: Path, old: str, new: str):
    text = path.read_text()
    if old not in text:
        return False
    path.write_text(text.replace(old, new))
    return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--old", required=True, help="substring to replace (e.g. localhost)")
    parser.add_argument("--new", required=True, help="replacement host or URL")
    parser.add_argument("--paths", nargs="+", required=True, help="files to process")
    args = parser.parse_args()

    for rel in args.paths:
        file_path = Path(rel)
        if not file_path.exists():
            print(f"skip (not found): {file_path}")
            continue
        changed = replace_in_file(file_path, args.old, args.new)
        print(f"{'updated' if changed else 'no change'}: {file_path}")
