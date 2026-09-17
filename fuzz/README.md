# Fuzzing

ArchiveWeaver uses ClusterFuzzLite with Atheris to exercise parsers and trust
boundaries with coverage-guided inputs. Pull requests run five minutes of
code-change fuzzing, and a scheduled job runs a longer batch campaign plus
corpus pruning weekly. Both jobs publish SARIF findings to code scanning.

The build is intentionally dependency-free: the digest-pinned ClusterFuzzLite
Python builder supplies Atheris and PyInstaller, while the project source and
fuzz targets are copied into the builder through an explicit allowlist. A
deny-by-default Docker context excludes unrelated repository and operator data.

Crashes are release blockers. Reproduce a downloaded testcase with the
ClusterFuzzLite helper, add the minimized input as a regression test, fix the
underlying boundary, and rerun both the ordinary test suite and the fuzzer.
