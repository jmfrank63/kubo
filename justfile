build:
    docker build -t kubo-amd64:master .

tag:
    docker tag kubo-amd64:master jmfrank63/kubo-amd64:master

push:
    docker push jmfrank63/kubo-amd64:master

all: build tag push
