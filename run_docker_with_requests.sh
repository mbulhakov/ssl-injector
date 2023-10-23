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

docker run  --privileged --platform=$DOCKER_PLATFORM --name=sslinj ssl-injector:latest & \
    sleep 5 && docker exec -d sslinj sh -c 'while true; do x=$(shuf -i 10-60 -n 1); sleep "0.$x"; curl --silent -X POST -H "Content-Type: application/json" -d "{\"key\": \"value\", \"random_number\": $x, \"timestamp\": \"\$(date)\"}" https://httpbin.org/post; done & while true; do limit=$(shuf -i 1-10 -n 1); sleep_time=$(shuf -i 50-99 -n 1); sleep "0.$sleep_time"; python3 -q -c "import requests; import time; limit = $limit; response = requests.get(f'"'"'https://v2.jokeapi.dev/joke/Any?blacklistFlags=nsfw,religious,political,racist,sexist,explicit&amount={limit}'"'"')"; done'