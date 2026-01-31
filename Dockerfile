FROM golang:1.25-alpine AS builder

WORKDIR /build

# Download dependencies first (better caching)
COPY go.mod go.sum* ./
RUN go mod download 2>/dev/null || true

# Build
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o webhook-proxy .

# Runtime image
FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app
COPY --from=builder /build/webhook-proxy .

# Create data directory
RUN mkdir -p /data

EXPOSE 8787

ENTRYPOINT ["/app/webhook-proxy"]
