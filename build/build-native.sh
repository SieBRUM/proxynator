#!/usr/bin/env bash
# Builds the native parts of the Linux capture modes for this machine's architecture into
# artifacts/native/linux-x64 or linux-arm64, where the .NET build picks them up (build/NativeArtifacts.targets):
#   proxynator.bpf.o           eBPF programs of the "ebpf" mode   (needs clang and libbpf-dev)
#   libproxynator-preload.so   LD_PRELOAD library of "preload"    (needs gcc)
# Ubuntu/Kali: sudo apt install clang llvm libbpf-dev gcc
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

case "$(uname -m)" in
  x86_64) target_arch=x86; rid=linux-x64 ;;
  aarch64) target_arch=arm64; rid=linux-arm64 ;;
  *) echo "unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac

out="$root/artifacts/native/$rid"
mkdir -p "$out"

clang -O2 -g -Wall -Werror -target bpf -D__TARGET_ARCH_${target_arch} \
  -I"/usr/include/$(uname -m)-linux-gnu" \
  -c "$root/native/linux/bpf/proxynator.bpf.c" -o "$out/proxynator.bpf.o"
# Drop DWARF, keep BTF (libbpf needs it for the CO-RE relocations).
llvm-strip -g "$out/proxynator.bpf.o" 2>/dev/null || true

gcc -std=c11 -O2 -g -Wall -Wextra -Werror -fPIC -shared -fvisibility=hidden -D_GNU_SOURCE \
  -o "$out/libproxynator-preload.so" "$root"/native/linux/preload/*.c -ldl -lpthread

echo "Linux capture parts are in $out"
