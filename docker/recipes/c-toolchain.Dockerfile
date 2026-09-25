# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
#
# Build-and-run image for the C recipes (recipes/vulnlab.yaml, curl.yaml, sqlite.yaml,
# libxml2.yaml; SPEC §13.2-13.3). Every toolchain dependency is baked in here, at image
# build time, because recipe builds and PoC runs always use `--network none`.
#
# The base image is the same pinned Fedora digest as docker/capture/Containerfile.
# UNVERIFIED: this image has not been built on the development machine (no container
# engine there); the sandbox CI job is the first place it is built.
FROM registry.fedoraproject.org/fedora:44@sha256:b4488a77fd2b96513fc8c18b502df7fbf19dad9e77d9a430c0163c574654822c

RUN dnf install -y --setopt=install_weak_deps=False \
        clang compiler-rt llvm libasan libubsan binutils make \
        autoconf automake libtool pkgconf-pkg-config m4 perl python3 tcl gawk \
        coreutils findutils diffutils sed grep \
    && dnf clean all

# No debuginfod lookups (there is no network at run time) and a stable locale. The
# sandbox runs everything as uid 65534 (nobody) with HOME on the /tmp tmpfs.
ENV DEBUGINFOD_URLS="" \
    LANG=C.UTF-8 \
    HOME=/tmp

USER 65534:65534
WORKDIR /work
