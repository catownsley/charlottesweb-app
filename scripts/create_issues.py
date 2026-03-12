import json
import re
import subprocess
from pathlib import Path

GH = "/opt/homebrew/bin/gh"
REPO = "catownsley/charlottesweb-app"
REPO_ROOT = Path(__file__).resolve().parents[1]
BASE = REPO_ROOT / "docs/tickets"
PHASE_FILES = sorted(BASE.glob("phase-*.md"))


def run(cmd: list[str]) -> str:
    return subprocess.check_output(cmd, text=True).strip()


def existing_titles() -> set[str]:
    titles = set()
    for state in ("open", "closed"):
        out = run(
            [
                GH,
                "issue",
                "list",
                "--repo",
                REPO,
                "--state",
                state,
                "--limit",
                "500",
                "--json",
                "title",
            ]
        )
        for item in json.loads(out):
            titles.add(item["title"].strip())
    return titles


def main() -> None:
    existing = existing_titles()
    created: list[tuple[str, str]] = []
    skipped: list[str] = []

    for phase_file in PHASE_FILES:
        text = phase_file.read_text(encoding="utf-8")
        phase_title = text.splitlines()[0].strip("# ").strip()
        matches = list(
            re.finditer(r"^##\s+(CW-\d{3})\s+(.+)$", text, flags=re.MULTILINE)
        )

        for index, match in enumerate(matches):
            code = match.group(1).strip()
            issue_title = f"[{code}] {match.group(2).strip()}"
            start = match.end()
            end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
            section = text[start:end].strip()
            body = f"**Phase:** {phase_title}\n\n" f"{section}\n"

            if issue_title in existing:
                skipped.append(issue_title)
                continue

            url = run(
                [
                    GH,
                    "issue",
                    "create",
                    "--repo",
                    REPO,
                    "--title",
                    issue_title,
                    "--body",
                    body,
                    "--label",
                    "ticket",
                ]
            )
            created.append((issue_title, url))
            existing.add(issue_title)

    print(f"CREATED {len(created)}")
    for title, url in created:
        print(f"- {title} -> {url}")

    print(f"SKIPPED {len(skipped)}")
    for title in skipped:
        print(f"- {title}")


if __name__ == "__main__":
    main()
