PLUGINS_DIR ?= .data/plugins

.PHONY: beaver beaver-plugin-antispam plugins test

beaver:
	go build -o beaver ./cmd/beaver

plugins: beaver-plugin-antispam

beaver-plugin-antispam:
	mkdir -p $(PLUGINS_DIR)
	go build -o $(PLUGINS_DIR)/beaver-plugin-antispam ./cmd/beaver-plugin-antispam

test:
	go test ./...
