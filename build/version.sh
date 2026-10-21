#!/usr/bin/env bash
# Prints the version of a CI build: <major>.<minor> from Directory.Build.props and the workflow run number as the
# patch for pushes to main (released), a pre-release suffix otherwise (never released).
#   build/version.sh   (reads GITHUB_RUN_NUMBER, GITHUB_REF and GITHUB_EVENT_NAME)
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
base="$(sed -n 's:.*<Version>\([0-9]*\.[0-9]*\)\.[0-9]*</Version>.*:\1:p' "$root/Directory.Build.props")"
run="${GITHUB_RUN_NUMBER:-0}"
if [[ "${GITHUB_EVENT_NAME:-}" == "push" && "${GITHUB_REF:-}" == "refs/heads/main" ]]; then
  echo "${base}.${run}"
else
  echo "${base}.0-ci.${run}"
fi
