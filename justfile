build:
    #!/usr/bin/env bash
    arch=$(uname -m)
    if [ "$arch" = "x86_64" ]; then
        arch="amd64"
    fi
    docker build -t kubo-"$arch":master .

tag:
    #!/usr/bin/env bash
    arch=$(uname -m)
    if [ "$arch" = "x86_64" ]; then
        arch="amd64"
    fi
    docker tag kubo-"$arch":master jmfrank63/kubo-"$arch":master

push:
    #!/usr/bin/env bash
    arch=$(uname -m)
    if [ "$arch" = "x86_64" ]; then
        arch="amd64"
    fi
    docker push jmfrank63/kubo-"$arch":master

all: build tag push
