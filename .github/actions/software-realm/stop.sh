#!/bin/bash

set -euo pipefail

SCRIPT_DIR=$(dirname "$0")
cd $SCRIPT_DIR

pids=($(cat pids))

echo "Stopping ${#pids[@]} realms..."

for pid in "${pids[@]}"; do
    kill "$pid"
done

echo "Stopped ${#pids[@]} realms!"

rm pids
rm outputs
