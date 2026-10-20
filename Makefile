PLUGINS_DIR ?= .data/plugins
WEB_DIST := internal/webui/dist

.PHONY: beaver beaver-go beaver-plugin-antispam plugins test integration web-dev web-build

# Mail stack + embedded admin UI (needs Node for web-build).
beaver: web-build
	go build -o beaver ./cmd/beaver

# Go binary only; embeds whatever is already in internal/webui/dist (no npm).
beaver-go:
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

web-dev:
	cd web && npm run dev

# Builds SvelteKit into internal/webui/dist for go:embed.
web-build:
	cd web && npm run build
	@test -f $(WEB_DIST)/index.html || (echo "web-build: missing $(WEB_DIST)/index.html" >&2; exit 1)
	@touch $(WEB_DIST)/.gitkeep # adapter-static wipes dist; keep the tracked embed placeholder
