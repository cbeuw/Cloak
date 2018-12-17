default: all

version=$(shell ver=$$(git log -n 1 --pretty=oneline --format=%D | awk -F, '{print $$1}' | awk '{print $$3}'); \
	if [ "$$ver" = "master" ] ; then \
	ver="master($$(git log -n 1 --pretty=oneline --format=%h))" ; \
	fi ; \
	echo $$ver)

client: 
	go build -ldflags "-X main.version=${version}" -o ./build/ck-client ./cmd/ck-client 

server: 
	go build -ldflags "-X main.version=${version}" -o ./build/ck-server ./cmd/ck-server

install:
	mv build/ck-* /usr/local/bin

all: client server

clean:
	rm -rf ./build/ck-*
