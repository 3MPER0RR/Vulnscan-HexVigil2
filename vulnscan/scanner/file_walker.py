import os
from pathlib import Path

SUPPORTED_EXTENSIONS = {
    ".c", ".cpp", ".h", ".hpp",
    ".py",
    ".js", ".ts", ".mjs", ".cjs",
    ".rs",
    ".java", ".kt",
}

IGNORED_DIRS = {
    ".git", ".svn", "node_modules", "__pycache__",
    "venv", ".venv", "dist", "build", "target",
    ".idea", ".vscode",
}


def walk_files(path: str) -> list[Path]:
    root = Path(path)
    results: list[Path] = []

    if root.is_file():
        if root.suffix in SUPPORTED_EXTENSIONS:
            results.append(root)
        return results

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        for fname in filenames:
            fpath = Path(dirpath) / fname
            if fpath.suffix in SUPPORTED_EXTENSIONS:
                results.append(fpath)

    return results