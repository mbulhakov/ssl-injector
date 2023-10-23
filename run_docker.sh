#!/bin/sh

# Get the host architecture using uname -a
ARCHITECTURE=$(uname -a)

# Set the default Docker platform
DOCKER_PLATFORM="linux/amd64"

# Check the architecture and set the platform
if [[ $ARCHITECTURE == *"x86_64"* || $ARCHITECTURE == *"amd64"* ]]; then
    DOCKER_PLATFORM="linux/amd64"
elif [[ $ARCHITECTURE == *"aarch64"* ]]; then
    DOCKER_PLATFORM="linux/arm64"
fi

# Check if the host is macOS and adjust the platform
if [[ "$OSTYPE" == "darwin"* ]]; then
    if [[ $(arch) == "arm64" ]]; then
        DOCKER_PLATFORM="linux/arm64"
    fi
    # If not ARM64, it will use the default values for x86_64
fi

docker run --privileged --platform=$DOCKER_PLATFORM ssl-injector:latest