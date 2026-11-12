#!/bin/sh
# Runs one fuzz target for a number of seconds (default 60) over its corpus and its seeds:
# new inputs go to fuzz/corpus/<target>, the committed fuzz/seeds/<target> are read alongside.
set -eu
target=${1:?usage: fuzz/run.sh <target> [seconds]}
seconds=${2:-60}
cd "$(dirname "$0")/.."
mkdir -p "fuzz/corpus/$target"
seeds=""
if [ -d "fuzz/seeds/$target" ]; then
  seeds="fuzz/seeds/$target"
fi
exec cargo +nightly fuzz run "$target" "fuzz/corpus/$target" $seeds -- -max_total_time="$seconds"
