BINARY  := dns-verify
CMD     := ./cmd/dns-verify
GOFLAGS := -trimpath

.PHONY: all build test lint fmt clean

all: build

build:
	go build $(GOFLAGS) -o $(BINARY) $(CMD)

test:
	go test ./... -count=1

lint:
	golangci-lint run ./...

fmt:
	go fmt ./...

clean:
	rm -f $(BINARY)