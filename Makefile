PLUGINS_DIR ?= .data/plugins
WEB_DIST := internal/webui/dist

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev)
DIST_ARCH ?= amd64
DIST_NAME := beavermail-$(VERSION)-linux-$(DIST_ARCH)
# Static Linux release binaries; -trimpath keeps build-machine paths out of them.
DIST_GO := CGO_ENABLED=0 GOOS=linux GOARCH=$(DIST_ARCH) go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: beaver beaver-go beaver-plugin-antispam plugins test integration web-dev web-build dist

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

# Release tarball: dist/$(DIST_NAME).tar.gz (+ .sha256) with binaries, systemd unit and install docs.
dist: web-build
	rm -rf dist/$(DIST_NAME) && mkdir -p dist/$(DIST_NAME)
	$(DIST_GO) -o dist/$(DIST_NAME)/beaver ./cmd/beaver
	$(DIST_GO) -o dist/$(DIST_NAME)/beaver-plugin-antispam ./cmd/beaver-plugin-antispam
	cp contrib/systemd/beavermail.service docs/install.md docs/api.md LICENSE dist/$(DIST_NAME)/
	tar -C dist --owner=0 --group=0 --numeric-owner -czf dist/$(DIST_NAME).tar.gz $(DIST_NAME)
	cd dist && sha256sum $(DIST_NAME).tar.gz > $(DIST_NAME).tar.gz.sha256

web-dev:
	cd web && npm run dev

# Builds SvelteKit into internal/webui/dist for go:embed.
web-build:
	cd web && npm run build
	@test -f $(WEB_DIST)/index.html || (echo "web-build: missing $(WEB_DIST)/index.html" >&2; exit 1)
	@touch $(WEB_DIST)/.gitkeep # adapter-static wipes dist; keep the tracked embed placeholder
