key:
    #!/usr/bin/env bash
    if [ ! -f handshake/keys/swarm.key ]; then
        mkdir -p ./handshake/keys
        if [ ! -d handshake/go-ipfs-swarm-key ]; then
            git clone https://github.com/Kubuxu/go-ipfs-swarm-key-gen ./handshake/go-ipfs-swarm-key-gen
        fi
        cd ./handshake/go-ipfs-swarm-key-gen
        go run ipfs-swarm-key-gen/main.go > ../keys/swarm.key
        chmod 600 ../keys/swarm.key
        cd -
        rm -rf ./handshake/go-ipfs-swarm-key-gen
    fi

build: key
    #!/usr/bin/env bash
    arch=$(uname -m)
    if [ "$arch" = "x86_64" ]; then
        arch1="x86_64"
        arch2="amd64"
        arch3="amd64"
    elif [ "$arch" = "arm64" ]; then
        arch1="aarch64"
        arch2="arm64"
        arch3="aarch64"
    fi
    docker build --build-arg ARCH="$arch1" -t kubo-"$arch2":master .

tag:
    #!/usr/bin/env bash
    arch=$(uname -m)
    if [ "$arch" = "x86_64" ]; then
        arch1="x86_64"
        arch2="amd64"
        arch3="amd64"
    elif [ "$arch" = "arm64" ]; then
        arch1="aarch64"
        arch2="arm64"
        arch3="aarch64"
    fi
    docker tag kubo-"$arch2":master jmfrank63/kubo-"$arch2":master

push: build tag
    #!/usr/bin/env bash
    arch=$(uname -m)
    if [ "$arch" = "x86_64" ]; then
        arch1="x86_64"
        arch2="amd64"
        arch3="amd64"
    elif [ "$arch" = "arm64" ]; then
        arch1="aarch64"
        arch2="arm64"
        arch3="aarch64"
    fi
    docker push jmfrank63/kubo-"$arch2":master

start-all:
    just --justfile handshake/nodes/justfile create-all-networks
    just --justfile handshake/nodes/bridge/justfile start-bridge
    just --justfile handshake/nodes/justfile start-all-nodes

stop-all:
    just --justfile handshake/nodes/justfile stop-all-nodes
    just --justfile handshake/nodes/bridge/justfile stop-bridge

remove-all:
    just --justfile handshake/client/justfile clean || true
    just --justfile handshake/server/justfile clean || true
    just --justfile handshake/nodes/bridge/justfile stop-bridge
    just --justfile handshake/nodes/bridge/justfile remove-bridge
    just --justfile handshake/nodes/justfile remove-all-nodes

renew-all: remove-all
    just --justfile handshake/client/justfile build
    just --justfile handshake/server/justfile build
    just --justfile handshake/nodes/bridge/justfile build
    just build
    just --justfile handshake/nodes/justfile create-all-networks
    just --justfile handshake/nodes/bridge/justfile start-bridge
    just --justfile handshake/nodes/justfile run-all-nodes
