#!/bin/sh
set -eu

if [ "$#" -ne 6 ]; then
    echo "usage: run_startup_repetitions_openbsd.sh BINARY POLICY_SCHEMA POLICY REQUEST_SCHEMA OUTPUT_DIR SOURCE_COMMIT" >&2
    exit 64
fi

binary=$1
policy_schema=$2
policy=$3
request_schema=$4
output_dir=$5
source_commit=$6
mkdir -p "$output_dir"
for mode in access-only transition-only runtime-only full-pbea; do
    : > "$output_dir/startup-$mode.jsonl"
done

iteration=1
while [ "$iteration" -le 30 ]; do
    for mode in access-only transition-only runtime-only full-pbea; do
        "$binary" --bench-child "$mode" "$policy_schema" "$policy" "$request_schema" \
            "$source_commit" 0 1 1 >> "$output_dir/startup-$mode.jsonl"
    done
    iteration=$((iteration + 1))
done
wc -l "$output_dir"/startup-*.jsonl
