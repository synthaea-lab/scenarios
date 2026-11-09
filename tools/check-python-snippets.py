#!/usr/bin/env python3
"""Compile and lint the Python embedded in the shell scripts.

Several scenarios carry their Python inline: a `<<'PY'` heredoc fed to `python3 -` or written
to a file, or a single-quoted `python3 -c '...'` string. That code stays inline on purpose
(moving it to a .py file would change the argv the agent sees), so this check is how it gets
compiled and linted at all.

What it extracts from every tracked *.sh but its own test (or from the files given on the
command line):

- the body of each quoted `<<'PY'` heredoc. `PY` is the one heredoc tag for Python: a heredoc
  fed to `python3` under any other tag is reported, so none slips past the check;
- the body of each single-quoted `python3 -c '...'` string (bash copies it verbatim), except
  in a comment or inside a heredoc body.

Each snippet is compiled. With `--ruff RUFF`, each is also written to a scratch file, padded
with blank lines so that ruff reports the line number of the shell script, and linted:

- heredocs with ruff's default rules (E4, E7, E9, F) except E401 (several modules on one
  `import` line), the house style of the shortest snippets;
- `-c` strings, which are argv and so frozen byte for byte, with the correctness rules only
  (E9, F63, F7, F82: syntax errors, undefined names, misplaced statements).

Run from the repository root:

    python3 tools/check-python-snippets.py [--ruff ruff] [FILE.sh ...]

Exits non-zero listing every problem. CI runs it on every push.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass

PYTHON_TAG = "PY"
# A quoted heredoc: `<<'TAG'` or `<<"TAG"`, optionally `<<-`. Unquoted heredocs expand `$`
# and backticks, so their body is not the bytes Python reads; none feeds Python today.
HEREDOC = re.compile(r"""<<-?\s*(['"])(\w+)\1""")
# `python3 -c '...'`, also through a renamed copy (`"$TOOLS/user-python3" -c '...'`). A
# single-quoted bash string has no escapes: it ends at the next `'`.
DASH_C = re.compile(r"""python3"?\s+-c\s+'([^']*)'""")

# The check's own test: its fixtures are broken snippets on purpose.
SELF_TEST = "tools/test-python-snippets.sh"

HEREDOC_RUFF = ["--select", "E4,E7,E9,F", "--ignore", "E401"]
DASH_C_RUFF = ["--select", "E9,F63,F7,F82"]


@dataclass
class Snippet:
    path: str
    line: int  # 1-based line of the shell script where the Python source starts
    kind: str  # "heredoc" or "-c"
    source: str


def extract(path: str, text: str) -> tuple[list[Snippet], list[str]]:
    """Return the Python snippets of one shell script, and the problems found on the way."""
    snippets: list[Snippet] = []
    problems: list[str] = []
    lines = text.splitlines(keepends=True)
    heredoc_lines: set[int] = set()  # 1-based lines of every heredoc body
    index = 0
    while index < len(lines):
        line = lines[index]
        match = HEREDOC.search(line)
        if not match:
            index += 1
            continue
        tag = match.group(2)
        strip_tabs = line[match.start():].startswith("<<-")
        end = next(
            (
                j
                for j in range(index + 1, len(lines))
                if (lines[j].lstrip("\t") if strip_tabs else lines[j]).rstrip("\n") == tag
            ),
            None,
        )
        if end is None:
            problems.append(f"{path}:{index + 1}: heredoc <<'{tag}' is never closed")
            break
        heredoc_lines.update(range(index + 2, end + 1))
        if tag == PYTHON_TAG:
            body = "".join(lines[index + 1:end])
            snippets.append(Snippet(path, index + 2, "heredoc", body))
        elif "python" in line:
            problems.append(
                f"{path}:{index + 1}: Python heredoc tagged '{tag}': tag it '{PYTHON_TAG}' "
                "so this check lints it"
            )
        index = end + 1

    for match in DASH_C.finditer(text):
        line_start = text.rfind("\n", 0, match.start()) + 1
        if text[line_start:match.start()].lstrip().startswith("#"):
            continue  # quoted in a comment, not run
        line = text.count("\n", 0, match.start(1)) + 1
        if line in heredoc_lines:
            continue  # text written somewhere by this script, not run by it
        snippets.append(Snippet(path, line, "-c", match.group(1)))
    return snippets, problems


def compile_problem(snippet: Snippet) -> str | None:
    # Pad so a SyntaxError carries the line number of the shell script.
    padded = "\n" * (snippet.line - 1) + snippet.source
    try:
        compile(padded, snippet.path, "exec")
    except SyntaxError as error:
        return f"{snippet.path}:{error.lineno}: {snippet.kind} snippet: {error.msg}"
    return None


def ruff_problems(ruff: str, snippets: list[Snippet]) -> list[str]:
    problems = []
    with tempfile.TemporaryDirectory(prefix="python-snippets-") as scratch:
        for kind, rules in (("heredoc", HEREDOC_RUFF), ("-c", DASH_C_RUFF)):
            files = []
            names = {}
            for number, snippet in enumerate(s for s in snippets if s.kind == kind):
                # The scratch file name carries the script path, so ruff's report points at it.
                # git prints `/` on every OS; also fold the native separator (`\` on Windows).
                flat = snippet.path.replace("/", "__").replace(os.sep, "__")
                name = f"{flat}.{kind.strip('-')}{number}.py"
                scratch_path = os.path.join(scratch, name)
                with open(scratch_path, "w", encoding="utf-8") as f:
                    f.write("\n" * (snippet.line - 1) + snippet.source)
                files.append(scratch_path)
                names[scratch_path] = snippet.path
            if not files:
                continue
            result = subprocess.run(
                [ruff, "check", "--no-cache", "--isolated", "--output-format", "concise",
                 *rules, *files],
                capture_output=True, text=True, check=False,
            )
            if result.returncode != 0:
                report = result.stdout + result.stderr
                for scratch_path, path in names.items():
                    report = report.replace(scratch_path, path)
                problems.extend(line for line in report.splitlines() if line.strip())
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--ruff", help="ruff executable: also lint the snippets")
    parser.add_argument("files", nargs="*", help="shell scripts (default: every tracked *.sh)")
    args = parser.parse_args()

    files = args.files or [
        path
        for path in subprocess.run(
            ["git", "ls-files", "*.sh"], check=True, capture_output=True, text=True,
        ).stdout.split()
        if path != SELF_TEST
    ]
    snippets: list[Snippet] = []
    problems: list[str] = []
    for path in files:
        with open(path, encoding="utf-8") as f:
            found, extract_problems = extract(path, f.read())
        snippets.extend(found)
        problems.extend(extract_problems)
    if not snippets:
        problems.append("no Python snippet found: the extraction is broken")

    problems.extend(p for p in map(compile_problem, snippets) if p)
    if args.ruff:
        problems.extend(ruff_problems(args.ruff, snippets))

    for problem in problems:
        print(problem)
    if problems:
        return 1
    counts = {kind: sum(s.kind == kind for s in snippets) for kind in ("heredoc", "-c")}
    print(f"{counts['heredoc']} heredoc and {counts['-c']} -c Python snippets compile"
          + (" and lint clean" if args.ruff else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
