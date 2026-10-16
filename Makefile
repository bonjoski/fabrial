.PHONY: all build test clean install doctor

VERSION ?= $(shell cat VERSION 2>/dev/null || echo "0.2.0")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")
DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS := -s -w \
	-X github.com/bonjoski/fabrial/pkg/version.Version=$(VERSION) \
	-X github.com/bonjoski/fabrial/pkg/version.Commit=$(COMMIT) \
	-X github.com/bonjoski/fabrial/pkg/version.BuildTime=$(DATE)

all: build test

build:
	@mkdir -p bin
	go build -ldflags "$(LDFLAGS)" -o bin/fabrial ./cmd/fabrial

test:
	go test -v ./...

doctor: build
	./bin/fabrial doctor

install: build
	install -d /usr/local/bin
	install -m 755 bin/fabrial /usr/local/bin/fabrial

clean:
	rm -rf bin/
