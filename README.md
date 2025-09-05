# Onion Forum

Lightweight, no-login forum for Tor. Fast to deploy, minimal dependencies, works great as a v3 onion service.

## Features

- Zero JavaScript by default, server‑rendered UI
- Posts + comments, pagination, categories
- CSRF protection, strict CSP, input sanitization (safe Markdown)
- SQLite storage (1 file), tiny resource usage
- One‑step Docker + built‑in Tor hidden service

## Requirements

- Docker Desktop (Windows/macOS) or Docker Engine + Compose (Linux)

## Quick start (2 commands)

1. Start services (web + tor):

```bash
docker compose up --build -d
```

1. Get your onion URL (open in Tor Browser):

```bash
docker compose exec tor sh -lc 'cat /var/lib/tor/hidden_service/hostname'
```

That’s it. The forum is available over your .onion address (port 80).

## Stop / reset

- Stop: `docker compose down`
- Reset data (removes all posts and regenerates the onion address):

```bash
docker compose down
docker volume rm onion_forum_data 
docker volume rm onion_tor_data
```

## Data & persistence

- Forum data (SQLite DB) and the app’s secret key live in the `forum_data` volume at `/data` inside the container.
- Tor hidden service keys and `hostname` live in the `tor_data` volume.
- A persistent SECRET_KEY is auto‑generated on first run and stored at `/data/secret_key` (no setup needed). You can still override with an environment variable if you prefer.


## Health check

The app exposes `GET /healthz` for a quick check. Example:

```bash
curl http://localhost:8080/healthz
```

## Troubleshooting

- Tor not ready yet: watch logs until “Bootstrapped 100%”.

```bash
docker compose logs -f tor
```

- Need the onion name again:

```bash
docker compose exec tor sh -lc 'cat /var/lib/tor/hidden_service/hostname'
```

- Port in use: change the host port mapping in `docker-compose.yml` (e.g., `8090:8080`).

## License

See `LICENSE` in this repository.
