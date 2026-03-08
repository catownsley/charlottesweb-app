#!/usr/bin/env python3
"""Remove emojis from markdown files."""
import re
from pathlib import Path

# Common emojis used in docs
EMOJI_PATTERN = re.compile(
    "["
    "\U0001F300-\U0001F9FF"  # Emojis
    "\u2600-\u26FF"  # Misc symbols
    "\u2700-\u27BF"  # Dingbats
    "\U0001F1E0-\U0001F1FF"  # Flags
    "]+",
    flags=re.UNICODE,
)

# Specific emojis to remove
SPECIFIC_EMOJIS = [
    "✅",
    "❌",
    "🚧",
    "🔄",
    "⏳",
    "📋",
    "🏗️",
    "🔒",
    "🎫",
    "🐛",
    "📍",
    "📖",
    "💚",
    "🌐",
    "🚀",
    "⚠️",
    "🔗",
    "🔥",
    "💡",
    "⚡",
    "📊",
    "🎯",
    "✨",
    "🤖",
    "🔍",
    "📅",
    "🔧",
    "🔴",
    "🟡",
    "📈",
    "🛡️",
    "📝",
    "💾",
    "📁",
    "🚨",
    "💻",
    "🧪",
    "📚",
    "💰",
    "🌟",
    "🎉",
    "🏃",
    "👥",
    "🔑",
    "📦",
    "⌨️",
    "🖥️",
    "☁️",
    "🐍",
]


def remove_emojis(text: str) -> str:
    """Remove all emojis from text."""
    # Remove unicode emojis
    text = EMOJI_PATTERN.sub("", text)

    # Remove specific emojis
    for emoji in SPECIFIC_EMOJIS:
        text = text.replace(emoji, "")

    # Clean up double spaces left after emoji removal
    text = re.sub(r"  +", " ", text)

    # Clean up space at start of lines
    text = re.sub(r"^[ ]+", "", text, flags=re.MULTILINE)

    return text


def process_file(filepath: Path) -> None:
    """Process a single markdown file to remove emojis."""
    content = filepath.read_text(encoding="utf-8")
    cleaned = remove_emojis(content)

    if content != cleaned:
        filepath.write_text(cleaned, encoding="utf-8")
        print(f"Cleaned: {filepath}")
    else:
        print(f"No changes: {filepath}")


def main() -> None:
    """Process all markdown files in the project."""
    root = Path(__file__).parent.parent

    # Find all markdown files
    markdown_files = list(root.rglob("*.md"))

    # Exclude some paths
    excluded = [".pytest_cache", "node_modules", ".venv", "venv"]
    markdown_files = [
        f for f in markdown_files if not any(exc in str(f) for exc in excluded)
    ]

    print(f"Processing {len(markdown_files)} markdown files...")

    for filepath in markdown_files:
        process_file(filepath)

    print(f"\nDone! Processed {len(markdown_files)} files.")


if __name__ == "__main__":
    main()
