#!/bin/sh
set -ex
ipfs config Addresses.API /ip4/0.0.0.0/tcp/5002
ipfs bootstrap rm --all
ipfs dag import /webui/webui.car
ipfs config --json Plugins.Plugins '{ "server": { "Config": {}, "Disabled": true } }'
