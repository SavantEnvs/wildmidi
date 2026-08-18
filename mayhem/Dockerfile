# syntax=docker/dockerfile:1.7
#
# Commit-image Dockerfile (SMALL form) -- builds ON TOP of the org C/C++ base
# image (ghcr.io/savantenvs/base), which already carries clang-19 + libFuzzer +
# ASan/UBSan runtimes + cmake/ninja/make.
#
# WildMIDI needs NOTHING else: with the player frontends off (mayhem/build.sh
# passes -DWANT_PLAYER=OFF) the library has no external dependencies beyond
# libm, its CMake build has no FetchContent/ExternalProject, and both the
# SoundFont2 (src/tsf) and Yamaha MA-FM (src/mafm) backends are in-tree. So this
# is a thin wrapper: no extra apt packages, no vendored toolchain, no network
# fetch of any kind -- the air-gapped PATCH re-run (SPEC 6.5) needs no cache.
#
# Build (from the repo root, on the `mayhem` branch):
#   DOCKER_BUILDKIT=1 docker build -f mayhem/Dockerfile \
#       --build-arg COMMIT=$(git rev-parse HEAD) \
#       [--build-arg SOURCE_DATE_EPOCH=$(date +%s)] \
#       -t mytag .

FROM ghcr.io/savantenvs/base:20260621

ARG COMMIT
ARG REPO_URL
# SOURCE_DATE_EPOCH stays an ARG (available to build.sh); an empty value breaks clang, so it is
# never baked as ENV -- build.sh unsets it when empty.
ARG SOURCE_DATE_EPOCH

# Sanitizer override: the base exports SANITIZER_FLAGS (ASan+UBSan, halting) as the default.
# Declared WITHOUT a default so an unset arg lets the base ENV flow through to build.sh, while an
# explicit --build-arg (including an EMPTY one, for a no-sanitizer build) overrides it.
ARG SANITIZER_FLAGS
ARG COVERAGE_FLAGS=
ARG MAYHEM_JOBS=

# Source enters from the build CONTEXT (the CI checkout): the FULL repo (incl. .git history) is
# copied to /mayhem; build.sh builds in place.
USER mayhem
WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

RUN bash mayhem/build.sh

# WildMIDI's own ctest suite + the mayhem/kat/ known-answer probe (both built above with NORMAL,
# non-sanitized flags) -- a failing suite fails the image.
RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh — repo ships no functional tests"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
