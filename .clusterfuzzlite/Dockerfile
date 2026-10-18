# ClusterFuzzLite's Python builder, pinned to the reviewed registry manifest.
# Refresh the digest with `docker buildx imagetools inspect` and review the
# resulting toolchain change before merging an update.
FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:79cc75a68ab65120da54f35d53f10c7536554ffe684eea5bae078a9a5ff82923

# Copy only fuzzing inputs. Repository-local credentials and generated
# deployment evidence are intentionally outside the image trust boundary.
COPY src $SRC/archiveweaver/src
COPY fuzz $SRC/archiveweaver/fuzz
COPY .clusterfuzzlite/build.sh $SRC/build.sh
WORKDIR $SRC/archiveweaver
