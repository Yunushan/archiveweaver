# ClusterFuzzLite's Python builder, pinned to the reviewed registry manifest.
# Refresh the digest with `docker buildx imagetools inspect` and review the
# resulting toolchain change before merging an update.
FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:21f6fab17ace4dc76e1c56de91ee95d3d03da021df94b41056ba036f6c6f55e9

# Copy only fuzzing inputs. Repository-local credentials and generated
# deployment evidence are intentionally outside the image trust boundary.
COPY src $SRC/archiveweaver/src
COPY fuzz $SRC/archiveweaver/fuzz
COPY .clusterfuzzlite/build.sh $SRC/build.sh
WORKDIR $SRC/archiveweaver
