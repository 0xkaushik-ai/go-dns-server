.PHONY: run build test fmt vet clean

## run: start on :1053 with the example zone and blocklist
run:
	go run ./cmd/dnsserver -zone examples/zones.txt -blocklist examples/blocklist.txt

## build: compile into ./bin
build:
	go build -o bin/dnsserver ./cmd/dnsserver

## test: run all tests with the race detector
test:
	go test -race ./...

## fmt: format all Go code
fmt:
	gofmt -w .

## vet: run static analysis
vet:
	go vet ./...

## clean: remove build output
clean:
	rm -rf bin
