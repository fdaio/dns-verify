BINARY  := dns-verify
CMD     := ./cmd/dns-verify
GOFLAGS := -trimpath

# Version stamped into the binary by --version. Overridden by the release build
# from the git tag, so the number a user sees always matches the tag.
VERSION ?= dev
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build test lint fmt check clean

all: build

build:
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BINARY) $(CMD)

test:
	go test ./... -count=1

lint:
	golangci-lint run ./...

fmt:
	go fmt ./...

# GitHub rejects a workflow whose job graph is broken before any job runs, and
# nothing in a build catches that, so it is checked here.
check:
	go run ./cmd/workflowcheck

clean:
	rm -f $(BINARY)