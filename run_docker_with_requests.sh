#!/bin/sh

docker run  --privileged --detach --name=sslinj ssl-injector:latest
sleep 3
docker exec --detach sslinj sh -c 'while true; do x=$(shuf -i 10-60 -n 1); sleep "0.$x"; curl --silent -X POST -H "Content-Type: application/json" -d "{\"key\": \"value\", \"random_number\": $x}" https://httpbin.org/post; done & while true; do limit=$(shuf -i 1-10 -n 1); sleep_time=$(shuf -i 50-99 -n 1); sleep "0.$sleep_time"; python3 -q -c "import requests; import time; limit = $limit; response = requests.get(f'"'"'https://v2.jokeapi.dev/joke/Any?blacklistFlags=nsfw,religious,political,racist,sexist,explicit&amount={limit}'"'"')"; done'
docker logs --follow sslinj & sleep 180
docker kill sslinj