FROM rust:1-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends protobuf-compiler libpcap-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY shared ./shared
COPY core ./core
WORKDIR /src/core
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/core/target/release/netspectre-core /usr/local/bin/netspectre-core
ENV NS_DB=/data/netspectre.db
ENTRYPOINT ["netspectre-core"]
CMD ["lo"]
