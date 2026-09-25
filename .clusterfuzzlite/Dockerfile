# ClusterFuzzLite's Python builder, pinned to the reviewed registry manifest.
# Refresh the digest with `docker buildx imagetools inspect` and review the
# resulting toolchain change before merging an update.
FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:2ad0b742d9375b89173186beafc97492fd9dfd0f38e1e77467594b784f376969

# Copy only fuzzing inputs. Repository-local credentials and generated
# deployment evidence are intentionally outside the image trust boundary.
COPY src $SRC/archiveweaver/src
COPY fuzz $SRC/archiveweaver/fuzz
COPY .clusterfuzzlite/build.sh $SRC/build.sh
WORKDIR $SRC/archiveweaver
