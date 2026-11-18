#!/bin/sh
# Vendor shared/ui (tokens.css, base.css, icons/) into the dashboard's static tree.
# The dashboard ships as a tarball with no access to shared/, so the copy lives in the package.
# tests/test_ui_vendor.py fails when this copy drifts from shared/ui. Run after changing shared/ui.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
src="$here/../../shared/ui"
dst="$here/../exp_dashboard/static/vendor/ui"
[ -d "$src" ] || { echo "sync-ui: $src not found" >&2; exit 1; }
rm -rf "$dst"
mkdir -p "$dst/icons"
cp "$src/tokens.css" "$src/base.css" "$dst/"
cp "$src"/icons/*.svg "$dst/icons/"
echo "sync-ui: copied tokens.css, base.css and $(ls "$dst/icons" | wc -l) icons to $dst"
