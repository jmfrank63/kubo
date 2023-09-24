arch := `echo ${ARCHFLAGS} | cut -d ' ' -f 2`

build:
    docker build -t kubo-{{arch}}:master .

tag:
    docker tag kubo-{{arch}}:master jmfrank63/kubo-{{arch}}:master

push:
    docker push jmfrank63/kubo-{{arch}}:master

all: build tag push
