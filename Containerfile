# ARG BASE_IMAGE=registry.access.redhat.com/ubi9/ubi
ARG BASE_IMAGE=registry.access.redhat.com/ubi8/ubi

# hadolint ignore=DL3006,DL3033,DL3003
FROM ${BASE_IMAGE} AS builder

# Install build dependencies (including zstd-devel for core compression)
# hadolint ignore=DL3033
RUN yum install -y make gcc zlib-devel libzstd-devel git bzip2 \
    && yum clean all

# Bootstrap: install SBCL 2.2.9 binary (works with glibc 2.28)
# hadolint ignore=DL3003
RUN cd /tmp && \
    curl -fSL -o sbcl-boot.tar.bz2 https://prdownloads.sourceforge.net/sbcl/sbcl-2.2.9-x86-64-linux-binary.tar.bz2 && \
    tar xjf sbcl-boot.tar.bz2 && \
    cd sbcl-2.2.9-x86-64-linux && \
    sh install.sh && \
    cd / && rm -rf /tmp/sbcl-*

# Build SBCL 2.6.3 from source with zstd compression support
# hadolint ignore=DL3003
RUN cd /tmp && \
    curl -fSL -o sbcl-src.tar.bz2 https://prdownloads.sourceforge.net/sbcl/sbcl-2.6.3-source.tar.bz2 && \
    tar xjf sbcl-src.tar.bz2 && \
    cd sbcl-2.6.3 && \
    sh make.sh --with-sb-core-compression --prefix=/usr/local && \
    sh install.sh && \
    cd / && rm -rf /tmp/sbcl-*

# Clone whistler
RUN git clone https://github.com/atgreen/whistler.git /opt/whistler

WORKDIR /build
COPY Makefile block-copyfail.lisp block-copyfail-elf.lisp /build/

# Build standalone binary with compressed core
RUN make build WHISTLER=/opt/whistler

# The binary is at /build/block-copyfail
# Copy it out with: podman cp <container>:/build/block-copyfail .

# FROM registry.access.redhat.com/ubi9/ubi-minimal:9.7 AS final
# COPY --from=builder /build/block-copyfail /app/block-copyfail
# CMD ["/app/block-copyfail"]
