# syntax=docker/dockerfile:1
FROM rust:1-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends protobuf-compiler libpcap-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY shared ./shared
COPY core ./core
WORKDIR /src/core
# Cache the crate downloads and compiled dependencies between builds, so a code change only
# recompiles NetSpectre itself instead of all ~300 dependencies.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/core/target \
    cargo build --release && cp target/release/netspectre-core /usr/local/bin/netspectre-core

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/bin/netspectre-core /usr/local/bin/netspectre-core
ENV NS_DB=/data/netspectre.db
ENTRYPOINT ["netspectre-core"]
CMD ["lo"]
