# BeaverMail admin UI

SvelteKit + Tailwind CSS + Preline + Lucide. Talks to `/api/v1` on the same origin.

## Dev (against local beaver)

1. Enable HTTP on beaver (`config.json`):

```json
"http": { "enabled": true, "listen": "127.0.0.1:8080" }
```

Requires `secrets.auth_key` (from `beaver init`).

2. Start beaver: `./beaver serve` (from data dir / with config). Default binary has API only; UI via Vite:

```bash
npm install
npm run dev
```

Open http://localhost:5173. Vite proxies `/api` to `http://127.0.0.1:8080` (override with `BEAVER_API_PROXY`).

## Embedded in beaver

From the repo root:

```bash
make beaver
```

Builds SvelteKit into `internal/webui/dist` and embeds it via `go:embed`. With `http.enabled`, open `http://127.0.0.1:8080/` (same listener as `/api/v1`).

## Lint / format

```bash
npm run lint
npm run lint:fix   # apply Biome fixes
```

Config: root `biome.json` (`css.parser.tailwindDirectives` for `@plugin` / `@apply` / `@source`).

## Build (UI assets only)

```bash
npm run build
# or: make web-build
```

Output: `internal/webui/dist/` (for `go:embed`).
