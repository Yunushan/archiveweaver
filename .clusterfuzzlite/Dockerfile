# ClusterFuzzLite's Python builder, pinned to the reviewed registry manifest.
# Refresh the digest with `docker buildx imagetools inspect` and review the
# resulting toolchain change before merging an update.
FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:886fc3577cf92a953493c908b2b49ca5781c00683bccbb60bc54a3c1d94e52c4

# Copy only fuzzing inputs. Repository-local credentials and generated
# deployment evidence are intentionally outside the image trust boundary.
COPY src $SRC/archiveweaver/src
COPY fuzz $SRC/archiveweaver/fuzz
COPY .clusterfuzzlite/build.sh $SRC/build.sh
WORKDIR $SRC/archiveweaver
