.PHONY: beaver test

beaver:
	go build -o beaver ./cmd/beaver

test:
	go test ./...
