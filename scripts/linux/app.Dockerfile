# Linux build environment for the whole app: the core image's toolchain plus
# what the window needs (WebKitGTK), Node.js for the interface, and a
# virtual display to start the result on (see scripts/linux-check.ps1 -App).
FROM node:22-bookworm-slim AS node

FROM rust:1-bookworm
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends \
      libpcap-dev pkg-config \
      libwebkit2gtk-4.1-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev libxdo-dev \
      build-essential file rpm rsync \
      xvfb xauth xdotool imagemagick fonts-dejavu-core libcap2-bin \
 && rm -rf /var/lib/apt/lists/* \
 && rustup component add clippy rustfmt
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx
# Not the repository's folders: those hold the Windows build and its
# node_modules. The source is copied to /work, the build goes to /target.
ENV CARGO_TARGET_DIR=/target
WORKDIR /work
