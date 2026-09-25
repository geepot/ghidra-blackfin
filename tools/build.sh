#!/usr/bin/env bash
# Build the Blackfin extension zip, and optionally install it.
#
#   tools/build.sh [--install]
#
# Compiles data/languages/blackfin.slaspec with Ghidra's support/sleigh (the .sla is a
# build product, never committed), stamps the Ghidra version into extension.properties
# and writes a reproducible dist/ghidra_<ver>_PUBLIC_Blackfin.zip. --install unpacks it
# into the per-user Extensions folder of that Ghidra version; restart Ghidra afterwards.
#
# Environment: GHIDRA_INSTALL_DIR  Ghidra install root (default: Homebrew's opt/ghidra)
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GHIDRA="${GHIDRA_INSTALL_DIR:-/opt/homebrew/opt/ghidra/libexec}"
[ -x "$GHIDRA/support/sleigh" ] || { echo "error: no Ghidra at $GHIDRA (set GHIDRA_INSTALL_DIR)" >&2; exit 1; }
VER=$(sed -n 's/^application.version=//p' "$GHIDRA/Ghidra/application.properties")

B="$ROOT/build/Blackfin"; ZIP="$ROOT/dist/ghidra_${VER}_PUBLIC_Blackfin.zip"
rm -rf "$ROOT/build" && mkdir -p "$B" "$ROOT/dist"
for f in LICENSE.txt NOTICE.md README.md Module.manifest extension.properties data lib ghidra_scripts; do cp -R "$ROOT/$f" "$B/"; done
sed -i.bak "s/@extversion@/$VER/" "$B/extension.properties" && rm "$B/extension.properties.bak"
"$GHIDRA/support/sleigh" "$B/data/languages/blackfin.slaspec" 2>&1 | grep -E "ERROR|WARN|Error" || true
[ -f "$B/data/languages/blackfin.sla" ] || { echo "error: sleigh compile failed" >&2; exit 1; }

python3 - "$ROOT/build" "$ZIP" <<'PY'
import os, sys, zipfile
root, out = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:   # fixed dates and modes: reproducible
    for d, dirs, files in sorted(os.walk(root)):
        dirs.sort()
        for name in [""] + sorted(f for f in files if not f.startswith(".")):
            path = os.path.join(d, name)
            arc = os.path.relpath(path, root) + ("/" if not name else "")
            if arc == "./":
                continue
            info = zipfile.ZipInfo(arc, (1980, 2, 1, 0, 0, 0))
            info.external_attr = (0o40755 << 16 | 0x10) if not name else 0o644 << 16
            z.writestr(info, b"" if not name else open(path, "rb").read(), zipfile.ZIP_DEFLATED)
PY
echo "built $ZIP ($(shasum -a 256 "$ZIP" | cut -c1-16))"

if [ "${1:-}" = "--install" ]; then
  case "$(uname)" in Darwin) BASE="$HOME/Library/ghidra" ;; *) BASE="${XDG_CONFIG_HOME:-$HOME/.config}/ghidra" ;; esac
  EXT="$BASE/ghidra_${VER}_PUBLIC/Extensions"
  mkdir -p "$EXT" && rm -rf "$EXT/Blackfin" && unzip -q -o "$ZIP" -d "$EXT"
  # Fresh mtimes: the zip's fixed 1980 dates would keep Ghidra's cached script classes.
  touch "$EXT"/Blackfin/ghidra_scripts/*
  echo "installed into $EXT; restart Ghidra"
fi
