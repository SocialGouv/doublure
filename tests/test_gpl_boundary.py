"""The GPL boundary (D7) is a property of the CODE, not of the prose.

`services/anonshield/**` is GPL-3.0: the upstream clone and our HTTP wrapper.
Everything else is MIT. What makes that mix lawful is the ABSENCE of imports —
the two sides only ever speak HTTP, in separate processes.

The README has asserted this from the start; nothing verified it. A legal
guarantee resting on a sentence is lost at the first
`from services.anonshield import …`, with nobody seeing it — and it is then
the WHOLE repository that becomes GPL.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: MIT side: what must import nothing from the GPL side.
MIT_SIDE = ("src", "hooks", "scripts", "go", "extension", "tests")

#: GPL side, excluding the upstream clone (gitignored, and entitled to import
#: itself).
GPL_SIDE = ROOT / "services" / "anonshield" / "wrapper"

_PY_IMPORT = re.compile(r"^\s*(?:from|import)\s+([\w.]+)", re.M)
#: Go import BLOCK, not any quoted string: `~/.anonshield` is the state
#: directory and it appears in comments and paths all over the guard.
_GO_BLOCK = re.compile(r'^import\s*\((.*?)^\)|^import\s+("[^"]+")', re.M | re.S)
_GO_PATH = re.compile(r'"([^"\n]+)"')

#: Modules on the GPL side: our wrapper, and upstream's package (`src.anon`),
#: which is not to be confused with our own `src.anonproxy`.
FORBIDDEN = ("services", "anonshield", "anon.", "src.anon.")


def _files(root: Path, suffix: str) -> list[Path]:
    if not root.exists():
        return []
    return [p for p in root.rglob(f"*{suffix}")
            if "upstream" not in p.parts and "__pycache__" not in p.parts]


def test_mit_side_imports_nothing_from_the_gpl_side():
    offences = []
    roots = [ROOT / name for name in MIT_SIDE]
    files = [p for root in roots for p in _files(root, ".py")]
    files += [p for p in ROOT.glob("*.py")]  # anthropic_walker.py and friends
    for py in files:
        for module in _PY_IMPORT.findall(py.read_text(encoding="utf-8")):
            if module.startswith(FORBIDDEN):
                offences.append(f"{py.relative_to(ROOT)} imports {module}")
    assert not offences, "D7 boundary crossed: " + " ; ".join(offences)


def _go_imports(source: str) -> list[str]:
    return [path
            for block, single in _GO_BLOCK.findall(source)
            for path in _GO_PATH.findall(block or single)]


def test_go_imports_nothing_from_the_gpl_side():
    offences = [f"{go.relative_to(ROOT)} imports {path}"
                for go in _files(ROOT / "go", ".go")
                for path in _go_imports(go.read_text(encoding="utf-8"))
                if "anonshield" in path]
    assert not offences, "D7 boundary crossed: " + " ; ".join(offences)


def test_the_go_check_reads_imports_and_not_prose():
    """`~/.anonshield` is the state directory: it is quoted all over the guard,
    in comments and in paths. A check that matched any quoted string would
    fail on prose and pass on nothing."""
    assert _go_imports('import (\n\t"os"\n\t"x/anonshield"\n)') == [
        "os", "x/anonshield"]
    assert _go_imports('// dir "~/.anonshield" is read here\nvar x = "y"') == []


def test_gpl_side_does_not_import_our_code():
    """The other direction: lawful, and still forbidden by D7.

    MIT is compatible with the GPL, so such an import would contaminate
    nothing. But it would make the two sides ONE program, and the process
    separation — what D7 actually says — would be a deployment detail.
    """
    offences = [f"{py.relative_to(ROOT)} imports {module}"
                for py in _files(GPL_SIDE, ".py")
                for module in _PY_IMPORT.findall(py.read_text(encoding="utf-8"))
                if module.startswith(("anonproxy", "src.anonproxy"))]
    assert not offences, "D7 boundary crossed: " + " ; ".join(offences)


def test_each_side_carries_its_licence():
    """An erased licence is an erased boundary."""
    assert (ROOT / "LICENSE").is_file(), "MIT licence missing from the root"
    gpl = (GPL_SIDE / "LICENSE").read_text(encoding="utf-8")
    assert "GNU GENERAL PUBLIC LICENSE" in gpl.upper()
    assert "Version 3" in gpl
