GO ?= go

.PHONY: build build-all
build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w" -o cork ./cmd/cork

build-all:
	VERSION=$(VERSION) ./scripts/build-all.sh
