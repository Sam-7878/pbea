#!/bin/sh
set -eu

if [ "$#" -ne 8 ]; then
    echo "usage: run_matrix_openbsd.sh BINARY HELPER POLICY_SCHEMA POLICY REQUEST_SCHEMA OUTPUT_DIR FIXTURE_ROOT SOURCE_COMMIT" >&2
    exit 64
fi

binary=$1
helper_source=$2
policy_schema=$3
policy=$4
request_schema=$5
output_dir=$6
fixture_root=$7
source_commit=$8

mkdir -p "$output_dir" "$output_dir/../logs" "$fixture_root/allowed" \
    "$fixture_root/outside" "$fixture_root/bin" "$fixture_root/markers" "$fixture_root/logs"
printf '%s\n' '{"controlled":true}' > "$fixture_root/allowed/input.json"
printf '%s\n' 'synthetic-controlled-secret' > "$fixture_root/outside/secret.txt"
cp "$helper_source" "$fixture_root/bin/marker-helper"
chmod 755 "$fixture_root/bin/marker-helper"

for mode in access-only transition-only full-pbea; do
    : > "$output_dir/$mode.jsonl"
done
: > "$output_dir/../logs/matrix-stderr.log"

iteration=1
while [ "$iteration" -le 30 ]; do
    scenario_number=0
    while [ "$scenario_number" -le 8 ]; do
        scenario="S$scenario_number"
        mode_index=0
        for mode in access-only transition-only full-pbea; do
            seed=$((200000 + iteration * 100 + scenario_number * 3 + mode_index))
            printf '[%s %s %s]\n' "$mode" "$scenario" "$iteration" >> "$output_dir/../logs/matrix-stderr.log"
            "$binary" "$mode" "$scenario" "$iteration" "$seed" "$policy_schema" "$policy" "$request_schema" \
                "$fixture_root" "$source_commit" >> "$output_dir/$mode.jsonl" \
                2>> "$output_dir/../logs/matrix-stderr.log"
            mode_index=$((mode_index + 1))
        done
        scenario_number=$((scenario_number + 1))
    done
    iteration=$((iteration + 1))
done

wc -l "$output_dir/access-only.jsonl" "$output_dir/transition-only.jsonl" "$output_dir/full-pbea.jsonl"
