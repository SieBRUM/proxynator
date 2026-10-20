#!/usr/bin/env bash
# Builds the Debian package (Ubuntu, Kali) from a self-contained linux-x64 publish directory that contains
# proxynatord, proxynator, proxynator.bpf.o and libproxynator-preload.so.
#   build/package-deb.sh <publish-dir> <version> [output-dir]
set -euo pipefail

publish="$(cd "$1" && pwd)"
version="$2"
output="${3:-.}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

for file in proxynatord proxynator proxynator.bpf.o libproxynator-preload.so; do
  [[ -e "$publish/$file" ]] || { echo "missing $publish/$file" >&2; exit 1; }
done

staging="$(mktemp -d)"
trap 'rm -rf "$staging"' EXIT
package="$staging/proxynator_${version}_amd64"

install -d "$package/opt/proxynator" "$package/usr/bin" "$package/usr/sbin" "$package/lib/systemd/system" \
  "$package/etc/proxynator" "$package/usr/share/doc/proxynator" "$package/DEBIAN"
cp -a "$publish/." "$package/opt/proxynator/"
ln -s /opt/proxynator/proxynator "$package/usr/bin/proxynator"
ln -s /opt/proxynator/proxynatord "$package/usr/sbin/proxynatord"
install -m 0644 "$root/packaging/linux/proxynatord.service" "$package/lib/systemd/system/proxynatord.service"
install -m 0640 "$root/packaging/linux/config.json" "$package/etc/proxynator/config.json"
install -m 0644 "$root/LICENSE" "$root/NOTICE" "$root/README.md" "$package/usr/share/doc/proxynator/"
install -d "$package/usr/share/doc/proxynator/samples"
install -m 0644 "$root"/samples/*.json "$package/usr/share/doc/proxynator/samples/"

cat > "$package/DEBIAN/control" <<CONTROL
Package: proxynator
Version: ${version}
Section: net
Priority: optional
Architecture: amd64
Depends: libc6, libbpf1 | libbpf0
Maintainer: The Proxynator Authors <https://github.com/SieBRUM/proxynator>
Homepage: https://github.com/SieBRUM/proxynator
Description: forces chosen applications' traffic through SOCKS/HTTP proxies
 Proxynator captures the outbound connections of the programs you choose (by
 rule) and sends them through SOCKS4/4a/5 or HTTP CONNECT proxies and chains,
 for analysis in Burp Suite, mitmproxy or through a pivot. It works for programs
 that ignore proxy settings: the ebpf mode captures in the kernel, the preload
 mode hooks programs started with 'proxynator run'.
CONTROL

echo "/etc/proxynator/config.json" > "$package/DEBIAN/conffiles"

cat > "$package/DEBIAN/postinst" <<'SCRIPT'
#!/bin/sh
set -e
if [ "$1" = "configure" ]; then
  # Members of this group can use the 'proxynator' CLI without sudo.
  getent group proxynator >/dev/null || addgroup --system proxynator >/dev/null
  chgrp proxynator /etc/proxynator/config.json
  if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null || true
  fi
  echo "proxynatord is installed but not started. Edit /etc/proxynator/config.json (samples in /usr/share/doc/proxynator/samples),"
  echo "then: sudo systemctl enable --now proxynatord. Add yourself to the 'proxynator' group to use the CLI without sudo."
fi
SCRIPT

cat > "$package/DEBIAN/prerm" <<'SCRIPT'
#!/bin/sh
set -e
if [ -d /run/systemd/system ] && systemctl is-active --quiet proxynatord; then
  systemctl stop proxynatord || true
fi
SCRIPT

cat > "$package/DEBIAN/postrm" <<'SCRIPT'
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload >/dev/null || true
fi
if [ "$1" = "purge" ]; then
  rm -rf /etc/proxynator
fi
SCRIPT

chmod 0755 "$package/DEBIAN/postinst" "$package/DEBIAN/prerm" "$package/DEBIAN/postrm"
mkdir -p "$output"
dpkg-deb --build --root-owner-group "$package" "$output/proxynator_${version}_amd64.deb"
