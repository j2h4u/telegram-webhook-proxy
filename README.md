# Telegram Webhook Proxy

A lightweight buffering proxy for Telegram Bot webhooks. Ensures webhook reliability by queuing messages when your bot is temporarily unavailable.

## Why?

Telegram expects webhook endpoints to respond quickly (within seconds). If your bot:
- Is restarting or deploying
- Temporarily overloaded
- Experiencing network issues

...Telegram will retry a few times, then **disable your webhook entirely**.

This proxy sits in front of your bot and:
1. Accepts webhooks immediately (always returns 200 OK to Telegram)
2. Tries to deliver to your bot instantly
3. If delivery fails, queues the message in SQLite
4. Retries delivery in the background until successful

## Architecture

```
Telegram ──► Webhook Proxy ──► Your Bot
                   │
                   ▼
              SQLite Queue
           (when bot is down)
```

## Quick Start

### With Docker Compose

1. Clone and configure:
```bash
git clone https://github.com/yourusername/telegram-webhook-proxy
cd telegram-webhook-proxy
cp .env.example .env
# Edit .env with your webhook secret
```

2. Run:
```bash
docker compose up -d
```

3. Point your Telegram webhook to the proxy instead of your bot.

### Configuration

All configuration via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `LISTEN_ADDR` | `:8787` | Address to listen on |
| `WEBHOOK_PATH` | `/telegram-webhook` | Path for incoming webhooks |
| `WEBHOOK_SECRET` | (empty) | Secret token for verification |
| `BACKEND_URL` | `http://openclaw-gateway:8787/telegram-webhook` | Your bot's webhook endpoint |
| `DB_PATH` | `/data/queue.db` | SQLite database path |
| `RETRY_INTERVAL` | `5s` | How often to retry queued messages |
| `MAX_RETRIES` | `100` | Max retry attempts before giving up |

### Docker Network Setup

For the proxy to reach your bot via Docker DNS, both containers must be on the same network:

```bash
# Create shared network
docker network create openclaw-network

# In your bot's docker-compose.yml, add:
networks:
  - openclaw-network

# The proxy is already configured to use this network
```

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /telegram-webhook` | Receives webhooks from Telegram |
| `GET /healthz` | Health check (returns `ok`) |
| `GET /stats` | Queue statistics (JSON) |

### Stats Response

```json
{
  "queued": 5,
  "pending": 3,
  "failed": 2,
  "backend_url": "http://openclaw-gateway:8787/telegram-webhook",
  "max_retries": 100
}
```

## Security

- Verifies `X-Telegram-Bot-Api-Secret-Token` header if `WEBHOOK_SECRET` is set
- Rejects requests with invalid or missing tokens
- Only exposes the webhook endpoint, not your bot's other APIs

## Building Locally

```bash
# Requires Go 1.25+
go build -o webhook-proxy .
./webhook-proxy
```

## License

MIT
