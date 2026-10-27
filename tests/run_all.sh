#!/usr/bin/env bash
# Run every test file and report a summary. No root needed; as root the
# end-to-end nftables/network-namespace tests run too.
# Usage: tests/run_all.sh [PYTHON]
PY="${1:-python3}"
cd "$(dirname "$0")/.." || exit 1
failed=""
for t in tests/test_*.py; do
  echo "################ $t"
  if "$PY" "$t"; then :; else failed="$failed $t"; fi
done
echo
if [ -z "$failed" ]; then echo "ALL TEST FILES PASSED"; else echo "FAILED:$failed"; exit 1; fi
