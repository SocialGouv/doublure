#!/usr/bin/env bash
# Install the arbitration extension into VSCodium or VS Code.
#
# By SYMLINK, not by copy. The extension is plain JavaScript with no build
# step, so a link means an edit here is live on the next window reload — and,
# more importantly, there is only ever one copy. A packaged .vsix would be a
# second artefact to keep in step with the repository, which is the whole
# reason this project generates rather than duplicates.
#
# The extension is a CONTROL SURFACE, never an enforcement point: uninstalling
# it must open nothing. That is the design test to repeat at every addition,
# and it is why installing it is this simple.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="${REPO}/extension"

# The folder name VS Code expects: publisher.name-version, read from the
# manifest so the two cannot disagree.
NAME="$(python3 -c '
import json, sys
m = json.load(open(sys.argv[1]))
print(m["publisher"] + "." + m["name"] + "-" + m["version"])
' "${SOURCE}/package.json")" || { echo "unreadable manifest" >&2; exit 1; }

installed=0
for dir in "${HOME}/.vscode-oss/extensions" "${HOME}/.vscode/extensions"; do
  [[ -d "${dir}" ]] || continue
  target="${dir}/${NAME}"
  # A stale directory from a previous version would win over the link.
  rm -rf "${target}"
  ln -s "${SOURCE}" "${target}"
  echo "→ linked ${target}"
  installed=$((installed + 1))
done

if [[ ${installed} -eq 0 ]]; then
  echo "install-extension: no VS Code or VSCodium extensions directory found." >&2
  echo "                   Looked in ~/.vscode-oss/extensions and ~/.vscode/extensions." >&2
  exit 1
fi

cat <<'FIN'

Reload the IDE window to pick it up:
  Ctrl+Shift+P → "Developer: Reload Window"

Then, with a project open:
  Ctrl+Shift+P → "anonproxy: arbitrate anonymised values"
                 "anonproxy: change mode"

It finds its socket on its own, from the open folder's path. Nothing to
configure — and if the control service is not running, it says so rather than
failing silently.
FIN
