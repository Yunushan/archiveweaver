#!/bin/bash -eu

# compile_python_fuzzer is supplied by the digest-pinned Python builder.
for harness in "$SRC"/archiveweaver/fuzz/*_fuzzer.py; do
  compile_python_fuzzer \
    "$harness" \
    --paths "$SRC/archiveweaver/src" \
    --paths "$SRC/archiveweaver/fuzz"
done
