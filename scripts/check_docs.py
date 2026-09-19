"""Fail CI when a tracked Markdown page links to a missing local file."""

from pathlib import Path
import re
import subprocess
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
LINK = re.compile(r"!?\[[^\]\n]*\]\(([^)\n]+)\)")


def main() -> None:
    tracked = subprocess.check_output(["git", "ls-files", "-z", "--", "*.md"], cwd=ROOT)
    failures = []
    for relative in (Path(value.decode("utf-8")) for value in tracked.split(b"\0") if value):
        document = ROOT / relative
        for target in LINK.findall(document.read_text(encoding="utf-8")):
            parsed = urlsplit(target)
            if parsed.scheme or parsed.netloc or not parsed.path:
                continue
            destination = document.parent / unquote(parsed.path)
            if not destination.is_file():
                failures.append(f"{relative}: {target}")
    if failures:
        raise SystemExit("Missing local Markdown targets:\n" + "\n".join(failures))
    print("Tracked Markdown links to local files: PASS")


if __name__ == "__main__":
    main()
