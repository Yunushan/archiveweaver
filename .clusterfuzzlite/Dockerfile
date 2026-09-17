# ClusterFuzzLite's Python builder, pinned to the reviewed registry manifest.
# Refresh the digest with `docker buildx imagetools inspect` and review the
# resulting toolchain change before merging an update.
FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:6b2b3a7e4a2da50de47f94925cffbe34747e1aae4f33d7f07ba6c681dd648b23

# Copy only fuzzing inputs. Repository-local credentials and generated
# deployment evidence are intentionally outside the image trust boundary.
COPY src $SRC/archiveweaver/src
COPY fuzz $SRC/archiveweaver/fuzz
COPY .clusterfuzzlite/build.sh $SRC/build.sh
WORKDIR $SRC/archiveweaver
