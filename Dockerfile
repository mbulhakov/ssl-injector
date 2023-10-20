FROM --platform=linux/arm64 rustlang/rust:nightly-bullseye as builder

RUN apt-get update \
    && apt-get install -y \
    software-properties-common \
    && wget https://apt.llvm.org/llvm.sh \
    && chmod +x llvm.sh \
    && ./llvm.sh 16 \
    && apt-get install -y \
    libssl-dev \
    musl \
    musl-dev \
    musl-tools \
    pkg-config
RUN rustup component add rust-src
RUN rustup target add aarch64-unknown-linux-musl
RUN cargo install bpf-linker
COPY . /src
WORKDIR /src
ENV LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/lib/llvm-16/lib/
#RUN cargo clippy --target=aarch64-unknown-linux-musl --workspace --exclude=ssl-injector -- -D warnings
RUN --mount=type=cache,target=/.root/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo xtask build-ebpf --release \
    && cargo build --release --target=aarch64-unknown-linux-musl \
    && cp /src/target/aarch64-unknown-linux-musl/release/ssl-injector /usr/sbin \
    && cp /src/log4rs.yml /usr/sbin

FROM --platform=linux/arm64 debian:bullseye
# runc links those libraries dynamically
RUN apt update && apt install -y curl
COPY --from=builder /usr/sbin/ssl-injector /usr/sbin/
COPY --from=builder /usr/sbin/log4rs.yml /etc
ENTRYPOINT [ "/usr/sbin/ssl-injector" ]