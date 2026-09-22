import os

import yara
import sys
from pathlib import Path

yara_dir = Path("/tmp/yara")
compiled_file = yara_dir / "rules.compiled"


def main(target: Path):
    MISP_URL = os.environ.get("MISP_URL", "https://localhost")

    # Find latest modification time among all .yar files
    yar_files = list(yara_dir.glob("*.yar"))

    if not yar_files:
        raise RuntimeError(f"No .yar files found in {yara_dir}")

    latest_yar_mtime = max(f.stat().st_mtime for f in yar_files)

    # Compile if compiled file doesn't exist or is older than the newest .yar file
    if not compiled_file.exists() or compiled_file.stat().st_mtime < latest_yar_mtime:
        print("Compiling YARA rules...")

        filepaths = {
            f.name: str(f)
            for f in yar_files
        }

        rules = yara.compile(filepaths=filepaths)
        rules.save(str(compiled_file))

        print(f"Saved compiled rules to {compiled_file}")
    else:
        print("Compiled rules are up to date.")

        rules = yara.load(str(compiled_file))

    matches = rules.match(str(target))

    for match in matches:
        print(f"\nEvent ID: {match.meta['event_id']}")
        print(f"Attribute ID: {match.meta['attr_uuid']}")
        print(f"MISP Link: {MISP_URL}/events/view/{match.meta['event_id']}/focus:{match.meta['attr_uuid']}")

        print("\nAll data:")
        print(match.meta)
        print(match.namespace)
        print(match.rule)
        print(match.strings)
        print(match.tags)


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <file>")
        sys.exit(1)

    target = Path(sys.argv[1])

    if not target.is_file():
        print(f"File does not exist: {target}")
        sys.exit(1)

    main(target)
