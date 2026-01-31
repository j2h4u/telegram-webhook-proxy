# Telegram Webhook Proxy

A lightweight buffering proxy for Telegram Bot webhooks. Ensures webhook reliability by queuing messages when your bot is temporarily unavailable.

## Features

- **Instant acknowledgment** — Always returns 200 OK to Telegram immediately
- **Automatic queuing** — Buffers messages when backend is unavailable
- **Exponential backoff** — Retries with increasing delays (1s → 2s → 4s → 8s → ... → 5m max)
- **Idempotency** — Deduplicates messages by `update_id` to prevent double processing
- **Auto-cleanup** — Removes expired messages and old deduplication entries
- **YAML configuration** — External config file for easy customization
- **Minimal footprint** — Single binary, SQLite storage, ~10MB Docker image

## Why?

Telegram expects webhook endpoints to respond quickly. If your bot:
- Is restarting or deploying
- Temporarily overloaded
- Experiencing network issues

...Telegram will retry a few times, then **disable your webhook entirely**.

This proxy sits in front of your bot and handles all the reliability concerns.

## Architecture

```
Telegram ──► Webhook Proxy ──► Your Bot
                   │
                   ▼
              SQLite Queue
           (buffered when bot is down)
```

## Quick Start

### 1. Clone and configure

```bash
git clone https://github.com/j2h4u/telegram-webhook-proxy
cd telegram-webhook-proxy

cp config.example.yaml config.yaml
cp .env.example .env
# Edit .env with your webhook secret
```

### 2. Edit config.yaml

```yaml
server:
  listen_addr: ":8787"
  webhook_path: "/telegram-webhook"

backend:
  url: "http://your-bot:8787/telegram-webhook"
  timeout: 30s

queue:
  message_ttl: 24h         # How long to keep undelivered messages
  max_retries: 20          # Give up after this many attempts
  initial_backoff: 1s      # First retry delay
  max_backoff: 5m          # Cap retry delay at 5 minutes
  backoff_multiplier: 2.0  # Double delay each attempt

deduplication:
  enabled: true
  window_ttl: 1h           # Remember update_ids for 1 hour
```

### 3. Run

```bash
docker compose up -d
```

### 4. Point Telegram to the proxy

Update your webhook URL to point to the proxy instead of your bot directly.

## Configuration

### YAML Config File

The proxy reads configuration from `/config/config.yaml` by default. See `config.example.yaml` for all options.

### Environment Variables

Environment variables override config file settings:

| Variable | Description |
|----------|-------------|
| `CONFIG_PATH` | Path to config file (default: `/config/config.yaml`) |
| `WEBHOOK_SECRET` | Secret token for Telegram verification |
| `LISTEN_ADDR` | Override server listen address |
| `WEBHOOK_PATH` | Override webhook path |
| `BACKEND_URL` | Override backend URL |
| `DB_PATH` | Override database path |
| `MESSAGE_TTL` | Override message TTL (e.g., `24h`) |

## Retry Behavior

The proxy uses exponential backoff for failed deliveries:

| Attempt | Delay |
|---------|-------|
| 1 | 1s |
| 2 | 2s |
| 3 | 4s |
| 4 | 8s |
| 5 | 16s |
| 6 | 32s |
| 7 | 64s |
| 8 | 128s |
| 9+ | 5m (capped) |

After `max_retries` attempts, the message is marked as failed but kept until `message_ttl` expires.

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /telegram-webhook` | Receives webhooks from Telegram |
| `GET /healthz` | Health check |
| `GET /stats` | Queue statistics |

### Stats Response

```json
{
  "queued": 5,
  "pending": 3,
  "failed": 2,
  "dedup_window_size": 150,
  "backend_url": "http://openclaw-gateway:8787/telegram-webhook",
  "max_retries": 20,
  "message_ttl": "24h0m0s",
  "deduplication": true
}
```

## Docker Network Setup

For the proxy to reach your bot via Docker DNS:

```bash
# Create shared network
docker network create openclaw-network

# Both containers must use this network
```

## Security

- Verifies `X-Telegram-Bot-Api-Secret-Token` header
- Rejects requests with invalid tokens
- Only the webhook endpoint is exposed

## License

MIT
