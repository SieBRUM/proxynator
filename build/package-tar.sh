#!/usr/bin/env bash
# Builds a .tar.gz for Linux distributions without a package (no installer: unpack anywhere, run as root) from a
# self-contained linux-x64 or linux-arm64 publish directory.
#   build/package-tar.sh <publish-dir> <version> <rid: linux-x64 | linux-arm64> [output-dir]
set -euo pipefail

publish="$(cd "$1" && pwd)"
version="$2"
rid="$3"
output="${4:-.}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

for file in proxynatord proxynator proxynator-gui proxynator.bpf.o libproxynator-preload.so; do
  [[ -e "$publish/$file" ]] || { echo "missing $publish/$file" >&2; exit 1; }
done

name="proxynator-${version}-${rid}"
staging="$(mktemp -d)"
trap 'rm -rf "$staging"' EXIT
install -d "$staging/$name/packaging" "$staging/$name/samples"
cp -a "$publish/." "$staging/$name/"
install -m 0644 "$root"/packaging/linux/* "$staging/$name/packaging/"
install -m 0644 "$root/src/Proxynator.Gui/Assets/proxynator.png" "$staging/$name/packaging/"
install -m 0644 "$root"/samples/*.json "$staging/$name/samples/"
install -m 0644 "$root/LICENSE" "$root/NOTICE" "$root/README.md" "$staging/$name/"

mkdir -p "$output"
tar -C "$staging" -czf "$output/$name.tar.gz" --owner=0 --group=0 "$name"
echo "$output/$name.tar.gz"
