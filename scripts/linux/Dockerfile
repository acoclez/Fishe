# Linux build environment for the core crate (see scripts/linux-check.ps1).
FROM rust:1-bookworm
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends libpcap-dev pkg-config \
 && rm -rf /var/lib/apt/lists/* \
 && rustup component add clippy rustfmt
# Not the repository's target folder: that one holds the Windows build.
ENV CARGO_TARGET_DIR=/target
WORKDIR /src
