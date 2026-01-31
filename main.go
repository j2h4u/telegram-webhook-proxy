package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type Config struct {
	ListenAddr    string
	WebhookPath   string
	SecretToken   string
	BackendURL    string
	DBPath        string
	RetryInterval time.Duration
	MaxRetries    int
}

type QueueItem struct {
	ID        int64
	Payload   []byte
	CreatedAt time.Time
	Attempts  int
}

type Proxy struct {
	config Config
	db     *sql.DB
	client *http.Client
	mu     sync.Mutex
}

func main() {
	config := Config{
		ListenAddr:    getEnv("LISTEN_ADDR", ":8787"),
		WebhookPath:   getEnv("WEBHOOK_PATH", "/telegram-webhook"),
		SecretToken:   getEnv("WEBHOOK_SECRET", ""),
		BackendURL:    getEnv("BACKEND_URL", "http://openclaw-gateway:8787/telegram-webhook"),
		DBPath:        getEnv("DB_PATH", "/data/queue.db"),
		RetryInterval: parseDuration(getEnv("RETRY_INTERVAL", "5s")),
		MaxRetries:    parseInt(getEnv("MAX_RETRIES", "100")),
	}

	log.Printf("Starting telegram-webhook-proxy")
	log.Printf("  Listen: %s%s", config.ListenAddr, config.WebhookPath)
	log.Printf("  Backend: %s", config.BackendURL)
	log.Printf("  DB: %s", config.DBPath)

	proxy, err := NewProxy(config)
	if err != nil {
		log.Fatalf("Failed to initialize proxy: %v", err)
	}
	defer proxy.Close()

	// Start background worker
	go proxy.processQueue()

	// HTTP server
	http.HandleFunc(config.WebhookPath, proxy.handleWebhook)
	http.HandleFunc("/healthz", proxy.handleHealth)
	http.HandleFunc("/stats", proxy.handleStats)

	log.Printf("Listening on %s", config.ListenAddr)
	if err := http.ListenAndServe(config.ListenAddr, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func NewProxy(config Config) (*Proxy, error) {
	db, err := sql.Open("sqlite", config.DBPath)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	// Create table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS queue (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			payload BLOB NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			attempts INTEGER DEFAULT 0
		)
	`)
	if err != nil {
		return nil, fmt.Errorf("create table: %w", err)
	}

	// Create index for faster polling
	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_queue_attempts ON queue(attempts)`)
	if err != nil {
		return nil, fmt.Errorf("create index: %w", err)
	}

	return &Proxy{
		config: config,
		db:     db,
		client: &http.Client{Timeout: 30 * time.Second},
	}, nil
}

func (p *Proxy) Close() error {
	return p.db.Close()
}

func (p *Proxy) handleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Verify secret token
	if p.config.SecretToken != "" {
		token := r.Header.Get("X-Telegram-Bot-Api-Secret-Token")
		if token != p.config.SecretToken {
			log.Printf("Invalid secret token from %s", r.RemoteAddr)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	// Read body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Failed to read body: %v", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Try to deliver immediately
	if p.tryDeliver(body, r.Header.Get("X-Telegram-Bot-Api-Secret-Token")) {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Queue for later
	if err := p.enqueue(body); err != nil {
		log.Printf("Failed to enqueue: %v", err)
		// Still return 200 to Telegram, we'll lose this update
		// but at least Telegram won't disable our webhook
	}

	w.WriteHeader(http.StatusOK)
}

func (p *Proxy) tryDeliver(payload []byte, secretToken string) bool {
	req, err := http.NewRequest(http.MethodPost, p.config.BackendURL, bytes.NewReader(payload))
	if err != nil {
		log.Printf("Failed to create request: %v", err)
		return false
	}

	req.Header.Set("Content-Type", "application/json")
	if secretToken != "" {
		req.Header.Set("X-Telegram-Bot-Api-Secret-Token", secretToken)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		log.Printf("Backend request failed: %v", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return true
	}

	log.Printf("Backend returned %d", resp.StatusCode)
	return false
}

func (p *Proxy) enqueue(payload []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	_, err := p.db.Exec("INSERT INTO queue (payload) VALUES (?)", payload)
	if err != nil {
		return err
	}

	log.Printf("Queued update for later delivery")
	return nil
}

func (p *Proxy) processQueue() {
	ticker := time.NewTicker(p.config.RetryInterval)
	defer ticker.Stop()

	for range ticker.C {
		p.processQueueBatch()
	}
}

func (p *Proxy) processQueueBatch() {
	p.mu.Lock()
	defer p.mu.Unlock()

	rows, err := p.db.Query(`
		SELECT id, payload, attempts
		FROM queue
		WHERE attempts < ?
		ORDER BY id ASC
		LIMIT 10
	`, p.config.MaxRetries)
	if err != nil {
		log.Printf("Failed to query queue: %v", err)
		return
	}
	defer rows.Close()

	var items []QueueItem
	for rows.Next() {
		var item QueueItem
		if err := rows.Scan(&item.ID, &item.Payload, &item.Attempts); err != nil {
			log.Printf("Failed to scan row: %v", err)
			continue
		}
		items = append(items, item)
	}

	for _, item := range items {
		if p.tryDeliver(item.Payload, p.config.SecretToken) {
			// Success - remove from queue
			if _, err := p.db.Exec("DELETE FROM queue WHERE id = ?", item.ID); err != nil {
				log.Printf("Failed to delete item %d: %v", item.ID, err)
			} else {
				log.Printf("Delivered queued update %d (attempt %d)", item.ID, item.Attempts+1)
			}
		} else {
			// Failed - increment attempts
			if _, err := p.db.Exec("UPDATE queue SET attempts = attempts + 1 WHERE id = ?", item.ID); err != nil {
				log.Printf("Failed to update attempts for %d: %v", item.ID, err)
			}
		}
	}
}

func (p *Proxy) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func (p *Proxy) handleStats(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()

	var total, pending, failed int
	p.db.QueryRow("SELECT COUNT(*) FROM queue").Scan(&total)
	p.db.QueryRow("SELECT COUNT(*) FROM queue WHERE attempts < ?", p.config.MaxRetries).Scan(&pending)
	p.db.QueryRow("SELECT COUNT(*) FROM queue WHERE attempts >= ?", p.config.MaxRetries).Scan(&failed)

	stats := map[string]interface{}{
		"queued":       total,
		"pending":      pending,
		"failed":       failed,
		"backend_url":  p.config.BackendURL,
		"max_retries":  p.config.MaxRetries,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func parseDuration(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 5 * time.Second
	}
	return d
}

func parseInt(s string) int {
	var n int
	fmt.Sscanf(s, "%d", &n)
	if n <= 0 {
		return 100
	}
	return n
}
