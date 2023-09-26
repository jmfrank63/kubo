#!/bin/sh
set -ex
ipfs bootstrap rm --all
ipfs dag import /webui/webui.car
ipfs config --json Plugins.Plugins '{ "client": { "Config": {}, "Disabled": true } }'
