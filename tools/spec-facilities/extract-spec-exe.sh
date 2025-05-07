#!/bin/bash

# Check if the correct number of arguments is passed (expecting 1 argument for destination)
if [ $# -ne 1 ]; then
    echo "Usage: $0 <destination_directory>"
    exit 1
fi

my_list=("600" "602" "605" "620" "623" "625" "631" "641" "648" "657")

DEST_DIR="$1"
# Check if the destination directory exists, if not create it
if [ ! -d "$DEST_DIR" ]; then
    echo "Destination directory does not exist, creating it..."
    mkdir -p "$DEST_DIR"
fi

cd /home/user/spec_cpu
source /home/user/spec_cpu/shrc


for item in "${my_list[@]}"; do
    echo "Benchmark: $item"
    go $item exe
    SOURCE_DIR="$(pwd)"

    echo "copying from $SOURCE_DIR to $DEST_DIR"

    cp -r "$SOURCE_DIR"/* "$DEST_DIR"
done
