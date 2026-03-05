"""Update existing GitHub issues to remove local path references."""
import json
import re
import subprocess

GH = "/opt/homebrew/bin/gh"
REPO = "catownsley/charlottesweb-app"


def run(cmd: list[str]) -> str:
    return subprocess.check_output(cmd, text=True).strip()


def main() -> None:
    # Fetch all issues with their bodies
    issues_json = run([
        GH, "issue", "list",
        "--repo", REPO,
        "--state", "all",
        "--limit", "300",
        "--json", "number,title,body"
    ])
    issues = json.loads(issues_json)

    updated = []

    for issue in issues:
        number = issue["number"]
        title = issue["title"]
        body = issue["body"]

        # Check if body contains local path reference
        if "/Users/ct/Python/charlottesweb-app/" in body or "Source: docs/tickets/" in body:
            # Remove lines starting with "Source:"
            lines = body.split("\n")
            clean_lines = []
            for line in lines:
                if line.startswith("Source:"):
                    continue
                clean_lines.append(line)

            # Also convert "Phase: X" to "**Phase:** X" for consistency
            clean_body = "\n".join(clean_lines)
            clean_body = re.sub(r'^Phase:\s+', '**Phase:** ', clean_body, flags=re.MULTILINE)

            # Remove any extra blank lines
            clean_body = re.sub(r'\n{3,}', '\n\n', clean_body).strip()

            # Update the issue
            try:
                run([
                    GH, "issue", "edit", str(number),
                    "--repo", REPO,
                    "--body", clean_body
                ])
                updated.append((number, title))
                print(f"✓ Updated #{number}: {title}")
            except Exception as e:
                print(f"✗ Failed #{number}: {e}")

    print(f"\n{len(updated)} issues updated successfully")


if __name__ == "__main__":
    main()
