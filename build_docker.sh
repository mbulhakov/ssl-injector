#!/bin/sh

# Get the host architecture using uname -a
ARCHITECTURE=$(uname -a)

# Set the default Docker platform and Rust target for x86_64 hosts
DOCKER_PLATFORM="linux/amd64"
CARGO_TARGET="x86_64-unknown-linux-musl"

# Check the architecture and set the platform and Rust target accordingly
if [[ $ARCHITECTURE == *"x86_64"* || $ARCHITECTURE == *"amd64"* ]]; then
    DOCKER_PLATFORM="linux/amd64"
    CARGO_TARGET="x86_64-unknown-linux-musl"
elif [[ $ARCHITECTURE == *"aarch64"* ]]; then
    DOCKER_PLATFORM="linux/arm64"
    CARGO_TARGET="aarch64-unknown-linux-musl"
fi

# Check if the host is macOS and adjust the platform and Rust target
if [[ "$OSTYPE" == "darwin"* ]]; then
    if [[ $(arch) == "arm64" ]]; then
        DOCKER_PLATFORM="linux/arm64"
        CARGO_TARGET="aarch64-unknown-linux-musl"
    fi
    # If not ARM64, it will use the default values for x86_64
fi

# Display the selected platform and Rust target
echo "Docker Build Platform: $DOCKER_PLATFORM"
echo "Rust Target: $CARGO_TARGET"

# Build the Docker image
docker build \
    --build-arg DOCKER_PLATFORM=$DOCKER_PLATFORM \
    --build-arg CARGO_TARGET=$CARGO_TARGET \
    --file ./Dockerfile.template \
    --progress=plain \
    --tag ssl-injector .