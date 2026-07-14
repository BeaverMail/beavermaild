PLUGINS_DIR ?= .data/plugins

.PHONY: beaver beaver-plugin-antispam plugins test integration

beaver:
	go build -o beaver ./cmd/beaver

plugins: beaver-plugin-antispam

beaver-plugin-antispam:
	mkdir -p $(PLUGINS_DIR)
	go build -o $(PLUGINS_DIR)/beaver-plugin-antispam ./cmd/beaver-plugin-antispam

test:
	go test ./...

integration:
	@for s in tests/integration/*.sh; do \
		echo "== $$s =="; \
		bash "$$s" || exit 1; \
	done
