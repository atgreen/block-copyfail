FROM registry.access.redhat.com/ubi8/ubi

# Install build dependencies (including zstd-devel for core compression)
RUN yum install -y make gcc zlib-devel libzstd-devel git bzip2 && yum clean all

# Bootstrap: install SBCL 2.2.9 binary (works with glibc 2.28)
RUN cd /tmp && \
    curl -fSL -o sbcl-boot.tar.bz2 https://prdownloads.sourceforge.net/sbcl/sbcl-2.2.9-x86-64-linux-binary.tar.bz2 && \
    tar xjf sbcl-boot.tar.bz2 && \
    cd sbcl-2.2.9-x86-64-linux && \
    sh install.sh && \
    cd / && rm -rf /tmp/sbcl-*

# Build SBCL 2.6.3 from source with zstd compression support
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
