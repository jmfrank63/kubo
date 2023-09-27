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

push: build tag
    #!/usr/bin/env bash
    arch=$(uname -m)
    if [ "$arch" = "x86_64" ]; then
        arch="amd64"
    fi
    docker push jmfrank63/kubo-"$arch":master

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
    just --justfile handshake/nodes/bridge/justfile push
    just push
    just --justfile handshake/nodes/justfile create-all-networks
    just --justfile handshake/nodes/bridge/justfile start-bridge
    just --justfile handshake/nodes/justfile run-all-nodes
