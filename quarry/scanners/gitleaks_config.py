"""Quarry's Gitleaks config: Gitleaks' own default rules, minus its path allowlist.

IMPROVEMENT-PLAN item 23. The built-in config carries a global allowlist of paths
Gitleaks never reads: node_modules/, bower_components/, vendored Go and Ruby trees,
virtualenvs, site-packages and every common lockfile. Quarry runs Gitleaks without the
target's config (D14), so this list applied to every scan, and a token committed in
any of those files was never reported. MEASURED, gitleaks 8.30.1: a ghp_ token in
node_modules/pkg/x.py and another in a package-lock.json `resolved` URL were both
missed. `[extend] useDefault = true` inherits the same allowlist, so extending the
default does not help; the config has to be a copy.

What stays: every rule, the value-level allowlists (`regexes`, `stopwords`), each
rule's own allowlist, and the path entries for binary and media formats, which hold
no text a secret rule can match. What goes: path entries that name text a human or a
package manager wrote.

Regenerate after upgrading Gitleaks, from the binary that will run:

    python -m quarry.scanners.gitleaks_config "$(which gitleaks)"

A path entry this module has not classified stops the regeneration, so a new
allowlist entry is a decision, not a silent carry-over.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

CONFIG = Path(__file__).with_name("gitleaks.toml")
VERSION_MARK = "# gitleaks-version: "

# The rules are a copy of Gitleaks' config/gitleaks.toml, so its notice travels with
# them. Text as shipped in Homebrew's gitleaks 8.30.1 LICENSE.
GITLEAKS_LICENSE = """\
MIT License

Copyright (c) 2019 Zachary Rice

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

# Kept: formats with no text for a secret rule to read.
KEEP = frozenset({
    r"(?i)\.(?:bmp|gif|jpe?g|png|svg|tiff?)$",
    r"(?i)\.(?:eot|[ot]tf|woff2?)$",
    r"(?i)\.(?:docx?|xlsx?|pdf|bin|socket|vsidx|v2|suo|wsuo|.dll|pdb|exe|gltf)$",
    r"\.gem$",
    r"(?:^|/)\.git$",
})

# Dropped: dependency trees, lockfiles, build wrappers and vendored libraries. A token
# in any of them is still a committed token, and the funnel's path-class stage, not
# the scanner, decides what to do with a hit there (D8).
DROP = frozenset({
    r"gitleaks\.toml",
    r"go\.(?:mod|sum|work(?:\.sum)?)$",
    r"(?:^|/)vendor/modules\.txt$",
    r"(?:^|/)vendor/(?:github\.com|golang\.org/x|google\.golang\.org|gopkg\.in|istio\.io"
    r"|k8s\.io|sigs\.k8s\.io)(?:/.*)?$",
    r"(?:^|/)gradlew(?:\.bat)?$",
    r"(?:^|/)gradle\.lockfile$",
    r"(?:^|/)mvnw(?:\.cmd)?$",
    r"(?:^|/)\.mvn/wrapper/MavenWrapperDownloader\.java$",
    r"(?:^|/)node_modules(?:/.*)?$",
    r"(?:^|/)(?:deno\.lock|npm-shrinkwrap\.json|package-lock\.json|pnpm-lock\.yaml"
    r"|yarn\.lock)$",
    r"(?:^|/)bower_components(?:/.*)?$",
    r"(?:^|/)(?:angular|bootstrap|jquery(?:-?ui)?|plotly|swagger-?ui)[a-zA-Z0-9.-]*"
    r"(?:\.min)?\.js(?:\.map)?$",
    r"(?:^|/)javascript\.json$",
    r"(?:^|/)(?:Pipfile|poetry)\.lock$",
    r"(?i)(?:^|/)(?:v?env|virtualenv)/lib(?:64)?(?:/.*)?$",
    r"(?i)(?:^|/)(?:lib(?:64)?/python[23](?:\.\d{1,2})+|python/[23](?:\.\d{1,2})+"
    r"/lib(?:64)?)(?:/.*)?$",
    r"(?i)(?:^|/)[a-z0-9_.]+-[0-9.]+\.dist-info(?:/.+)?$",
    r"(?:^|/)vendor/(?:bundle|ruby)(?:/.*?)?$",
    r"verification-metadata\.xml",
    r"Database.refactorlog",
})


def extract_default(binary: Path) -> str:
    """Gitleaks embeds config/gitleaks.toml in its binary (go:embed). Read it out as
    the run of text around its title line."""
    b = binary.read_bytes()
    i = b.find(b'title = "gitleaks config"')
    if i < 0:
        raise ValueError(f"{binary}: no embedded default config found")

    def text(c: int) -> bool:
        return 32 <= c < 127 or c in (9, 10, 13)
    s, e = i, i
    while s > 0 and text(b[s - 1]):
        s -= 1
    while e < len(b) and text(b[e]):
        e += 1
    cfg = b[s:e].decode()
    if "\n[allowlist]\n" not in cfg or "[[rules]]" not in cfg:
        raise ValueError(f"{binary}: embedded config is not in the expected shape")
    return cfg


def build(default: str, version: str) -> str:
    """The default config with every DROP entry removed from the global allowlist's
    `paths`. Raises on a path entry in neither KEEP nor DROP."""
    lines = default.splitlines(keepends=True)
    start = next(n for n, ln in enumerate(lines) if ln.strip() == "[allowlist]")
    open_ = next(n for n in range(start, len(lines)) if lines[n].startswith("paths = ["))
    close = next(n for n in range(open_, len(lines)) if lines[n].strip() == "]")
    kept, dropped, unknown = [], [], []
    for ln in lines[open_ + 1:close]:
        entry = ln.strip().rstrip(",").removeprefix("'''").removesuffix("'''")
        if entry in KEEP:
            kept.append(ln)
        elif entry in DROP:
            dropped.append(entry)
        else:
            unknown.append(entry)
    if unknown:
        raise ValueError("unclassified allowlist path(s); add each to KEEP or DROP: "
                         + ", ".join(unknown))
    header = [
        "# Generated by quarry/scanners/gitleaks_config.py from the default config\n",
        "# built into the gitleaks binary below. Do not edit by hand; regenerate.\n",
        f"{VERSION_MARK}{version}\n",
        "# Removed from the global [allowlist] paths, so these are scanned:\n",
        *(f"#   {d}\n" for d in sorted(dropped)),
        "#\n",
        "# The rules below are from Gitleaks (github.com/gitleaks/gitleaks):\n",
        "#\n",
        *(f"#   {ln}".rstrip() + "\n" for ln in GITLEAKS_LICENSE.splitlines()),
        "#\n",
    ]
    return "".join(header + lines[:open_ + 1] + kept + lines[close:])


def config_version(text: str) -> str | None:
    for ln in text.splitlines()[:10]:
        if ln.startswith(VERSION_MARK):
            return ln[len(VERSION_MARK):].strip()
    return None


def main(argv: list[str]) -> int:
    binary = Path(argv[1]) if len(argv) > 1 else None
    if binary is None or not binary.is_file():
        print("usage: python -m quarry.scanners.gitleaks_config <gitleaks binary>")
        return 2
    version = subprocess.run([str(binary), "version"], capture_output=True, text=True,
                             timeout=20, check=True).stdout.strip()
    CONFIG.write_text(build(extract_default(binary), version))
    print(f"wrote {CONFIG} from gitleaks {version}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
