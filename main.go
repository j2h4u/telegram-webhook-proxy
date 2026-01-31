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
	"gopkg.in/yaml.v3"
)

type Config struct {
	Server struct {
		ListenAddr  string `yaml:"listen_addr"`
		WebhookPath string `yaml:"webhook_path"`
	} `yaml:"server"`

	Backend struct {
		URL     string        `yaml:"url"`
		Timeout time.Duration `yaml:"timeout"`
	} `yaml:"backend"`

	Queue struct {
		DBPath           string        `yaml:"db_path"`
		RetryInterval    time.Duration `yaml:"retry_interval"`
		MaxRetries       int           `yaml:"max_retries"`
		MessageTTL       time.Duration `yaml:"message_ttl"`
		InitialBackoff   time.Duration `yaml:"initial_backoff"`
		MaxBackoff       time.Duration `yaml:"max_backoff"`
		BackoffMultiplier float64      `yaml:"backoff_multiplier"`
	} `yaml:"queue"`

	Security struct {
		WebhookSecret string `yaml:"webhook_secret"`
	} `yaml:"security"`

	Deduplication struct {
		Enabled   bool          `yaml:"enabled"`
		WindowTTL time.Duration `yaml:"window_ttl"`
	} `yaml:"deduplication"`
}

type TelegramUpdate struct {
	UpdateID int64 `json:"update_id"`
}

type QueueItem struct {
	ID        int64
	UpdateID  int64
	Payload   []byte
	CreatedAt time.Time
	Attempts  int
	NextRetry time.Time
}

type Proxy struct {
	config Config
	db     *sql.DB
	client *http.Client
	mu     sync.Mutex
}

// Log helpers with levels
func logInfo(format string, v ...interface{}) {
	log.Printf("[INFO] "+format, v...)
}

func logWarn(format string, v ...interface{}) {
	log.Printf("[WARN] "+format, v...)
}

func logError(format string, v ...interface{}) {
	log.Printf("[ERROR] "+format, v...)
}

func main() {
	configPath := getEnv("CONFIG_PATH", "/config/config.yaml")

	config, err := loadConfig(configPath)
	if err != nil {
		logWarn("Config file not found or invalid (%s), using defaults/env", configPath)
		config = defaultConfig()
	}

	// Environment variables override config file
	applyEnvOverrides(&config)

	logInfo("Starting telegram-webhook-proxy")
	listenDisplay := config.Server.ListenAddr
	if listenDisplay[0] == ':' {
		listenDisplay = "0.0.0.0" + listenDisplay
	}
	logInfo("  Listen: %s%s", listenDisplay, config.Server.WebhookPath)
	logInfo("  Backend: %s (timeout: %s)", config.Backend.URL, config.Backend.Timeout)
	logInfo("  Queue DB: %s", config.Queue.DBPath)
	logInfo("  Retry: every %s, max %d attempts", config.Queue.RetryInterval, config.Queue.MaxRetries)
	logInfo("  Backoff: %s → ×%.1f → max %s", config.Queue.InitialBackoff, config.Queue.BackoffMultiplier, config.Queue.MaxBackoff)
	logInfo("  Message TTL: %s", config.Queue.MessageTTL)
	logInfo("  Deduplication: %v (window: %s)", config.Deduplication.Enabled, config.Deduplication.WindowTTL)

	proxy, err := NewProxy(config)
	if err != nil {
		log.Fatalf("Failed to initialize proxy: %v", err)
	}
	defer proxy.Close()

	// Start background workers
	go proxy.processQueue()
	go proxy.cleanupLoop()

	// HTTP server
	http.HandleFunc(config.Server.WebhookPath, proxy.handleWebhook)
	http.HandleFunc("/healthz", proxy.handleHealth)
	http.HandleFunc("/stats", proxy.handleStats)

	logInfo("Listening on %s", config.Server.ListenAddr)
	if err := http.ListenAndServe(config.Server.ListenAddr, nil); err != nil {
		log.Fatalf("[FATAL] Server failed: %v", err)
	}
}

func loadConfig(path string) (Config, error) {
	var config Config

	data, err := os.ReadFile(path)
	if err != nil {
		return config, err
	}

	if err := yaml.Unmarshal(data, &config); err != nil {
		return config, err
	}

	return config, nil
}

func defaultConfig() Config {
	return Config{
		Server: struct {
			ListenAddr  string `yaml:"listen_addr"`
			WebhookPath string `yaml:"webhook_path"`
		}{
			ListenAddr:  ":8787",
			WebhookPath: "/telegram-webhook",
		},
		Backend: struct {
			URL     string        `yaml:"url"`
			Timeout time.Duration `yaml:"timeout"`
		}{
			URL:     "http://openclaw-gateway:8787/telegram-webhook",
			Timeout: 30 * time.Second,
		},
		Queue: struct {
			DBPath           string        `yaml:"db_path"`
			RetryInterval    time.Duration `yaml:"retry_interval"`
			MaxRetries       int           `yaml:"max_retries"`
			MessageTTL       time.Duration `yaml:"message_ttl"`
			InitialBackoff   time.Duration `yaml:"initial_backoff"`
			MaxBackoff       time.Duration `yaml:"max_backoff"`
			BackoffMultiplier float64      `yaml:"backoff_multiplier"`
		}{
			DBPath:            "/data/queue.db",
			RetryInterval:     5 * time.Second,
			MaxRetries:        20,
			MessageTTL:        24 * time.Hour,
			InitialBackoff:    1 * time.Second,
			MaxBackoff:        5 * time.Minute,
			BackoffMultiplier: 2.0,
		},
		Security: struct {
			WebhookSecret string `yaml:"webhook_secret"`
		}{},
		Deduplication: struct {
			Enabled   bool          `yaml:"enabled"`
			WindowTTL time.Duration `yaml:"window_ttl"`
		}{
			Enabled:   true,
			WindowTTL: 1 * time.Hour,
		},
	}
}

func applyEnvOverrides(config *Config) {
	if v := os.Getenv("LISTEN_ADDR"); v != "" {
		config.Server.ListenAddr = v
	}
	if v := os.Getenv("WEBHOOK_PATH"); v != "" {
		config.Server.WebhookPath = v
	}
	if v := os.Getenv("BACKEND_URL"); v != "" {
		config.Backend.URL = v
	}
	if v := os.Getenv("WEBHOOK_SECRET"); v != "" {
		config.Security.WebhookSecret = v
	}
	if v := os.Getenv("DB_PATH"); v != "" {
		config.Queue.DBPath = v
	}
	if v := os.Getenv("RETRY_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			config.Queue.RetryInterval = d
		}
	}
	if v := os.Getenv("MAX_RETRIES"); v != "" {
		var n int
		fmt.Sscanf(v, "%d", &n)
		if n > 0 {
			config.Queue.MaxRetries = n
		}
	}
	if v := os.Getenv("MESSAGE_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			config.Queue.MessageTTL = d
		}
	}
}

func NewProxy(config Config) (*Proxy, error) {
	db, err := sql.Open("sqlite", config.Queue.DBPath)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	// Create tables
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS queue (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			update_id INTEGER,
			payload BLOB NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			next_retry DATETIME DEFAULT CURRENT_TIMESTAMP,
			attempts INTEGER DEFAULT 0
		);

		CREATE TABLE IF NOT EXISTS seen_updates (
			update_id INTEGER PRIMARY KEY,
			seen_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE INDEX IF NOT EXISTS idx_queue_next_retry ON queue(next_retry);
		CREATE INDEX IF NOT EXISTS idx_queue_created ON queue(created_at);
		CREATE INDEX IF NOT EXISTS idx_seen_at ON seen_updates(seen_at);
	`)
	if err != nil {
		return nil, fmt.Errorf("create tables: %w", err)
	}

	return &Proxy{
		config: config,
		db:     db,
		client: &http.Client{Timeout: config.Backend.Timeout},
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
	if p.config.Security.WebhookSecret != "" {
		token := r.Header.Get("X-Telegram-Bot-Api-Secret-Token")
		if token != p.config.Security.WebhookSecret {
			logWarn("Invalid secret token from %s", r.RemoteAddr)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	// Read body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		logError("Failed to read body: %v", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Extract update_id for deduplication
	var update TelegramUpdate
	if err := json.Unmarshal(body, &update); err != nil {
		logWarn("Failed to parse update: %v", err)
		// Still try to process even if we can't parse
		update.UpdateID = 0
	}

	// Check for duplicate
	if p.config.Deduplication.Enabled && update.UpdateID > 0 {
		if p.isDuplicate(update.UpdateID) {
			logInfo("Duplicate update_id=%d, skipping", update.UpdateID)
			w.WriteHeader(http.StatusOK)
			return
		}
		p.markSeen(update.UpdateID)
	}

	// Try to deliver immediately
	if p.tryDeliver(body) {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Queue for later
	if err := p.enqueue(update.UpdateID, body); err != nil {
		logError("Failed to enqueue: %v", err)
	}

	w.WriteHeader(http.StatusOK)
}

func (p *Proxy) isDuplicate(updateID int64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	var count int
	err := p.db.QueryRow("SELECT COUNT(*) FROM seen_updates WHERE update_id = ?", updateID).Scan(&count)
	if err != nil {
		logError("Failed to check duplicate: %v", err)
		return false
	}
	return count > 0
}

func (p *Proxy) markSeen(updateID int64) {
	p.mu.Lock()
	defer p.mu.Unlock()

	_, err := p.db.Exec("INSERT OR IGNORE INTO seen_updates (update_id) VALUES (?)", updateID)
	if err != nil {
		logError("Failed to mark seen: %v", err)
	}
}

func (p *Proxy) tryDeliver(payload []byte) bool {
	req, err := http.NewRequest(http.MethodPost, p.config.Backend.URL, bytes.NewReader(payload))
	if err != nil {
		logError("Failed to create request: %v", err)
		return false
	}

	req.Header.Set("Content-Type", "application/json")
	if p.config.Security.WebhookSecret != "" {
		req.Header.Set("X-Telegram-Bot-Api-Secret-Token", p.config.Security.WebhookSecret)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		logWarn("Backend request failed: %v", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return true
	}

	logWarn("Backend returned %d", resp.StatusCode)
	return false
}

func (p *Proxy) enqueue(updateID int64, payload []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Check if already in queue (by update_id)
	if updateID > 0 {
		var count int
		p.db.QueryRow("SELECT COUNT(*) FROM queue WHERE update_id = ?", updateID).Scan(&count)
		if count > 0 {
			logInfo("Update %d already in queue, skipping", updateID)
			return nil
		}
	}

	_, err := p.db.Exec("INSERT INTO queue (update_id, payload) VALUES (?, ?)", updateID, payload)
	if err != nil {
		return err
	}

	logInfo("Queued update_id=%d for later delivery", updateID)
	return nil
}

func (p *Proxy) processQueue() {
	ticker := time.NewTicker(p.config.Queue.RetryInterval)
	defer ticker.Stop()

	for range ticker.C {
		p.processQueueBatch()
	}
}

func (p *Proxy) processQueueBatch() {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	rows, err := p.db.Query(`
		SELECT id, update_id, payload, attempts
		FROM queue
		WHERE attempts < ? AND next_retry <= ?
		ORDER BY next_retry ASC
		LIMIT 10
	`, p.config.Queue.MaxRetries, now)
	if err != nil {
		logError("Failed to query queue: %v", err)
		return
	}
	defer rows.Close()

	var items []QueueItem
	for rows.Next() {
		var item QueueItem
		if err := rows.Scan(&item.ID, &item.UpdateID, &item.Payload, &item.Attempts); err != nil {
			logError("Failed to scan row: %v", err)
			continue
		}
		items = append(items, item)
	}

	for _, item := range items {
		if p.tryDeliver(item.Payload) {
			if _, err := p.db.Exec("DELETE FROM queue WHERE id = ?", item.ID); err != nil {
				logError("Failed to delete item %d: %v", item.ID, err)
			} else {
				logInfo("Delivered queued update_id=%d (attempt %d)", item.UpdateID, item.Attempts+1)
			}
		} else {
			// Calculate next retry with exponential backoff
			nextBackoff := p.calculateBackoff(item.Attempts + 1)
			nextRetry := now.Add(nextBackoff)

			if _, err := p.db.Exec(
				"UPDATE queue SET attempts = attempts + 1, next_retry = ? WHERE id = ?",
				nextRetry, item.ID,
			); err != nil {
				logError("Failed to update item %d: %v", item.ID, err)
			} else {
				logWarn("Retry scheduled for update_id=%d in %s (attempt %d)",
					item.UpdateID, nextBackoff, item.Attempts+1)
			}
		}
	}
}

func (p *Proxy) calculateBackoff(attempt int) time.Duration {
	backoff := float64(p.config.Queue.InitialBackoff)
	for i := 1; i < attempt; i++ {
		backoff *= p.config.Queue.BackoffMultiplier
	}

	if time.Duration(backoff) > p.config.Queue.MaxBackoff {
		return p.config.Queue.MaxBackoff
	}
	return time.Duration(backoff)
}

func (p *Proxy) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		p.cleanup()
	}
}

func (p *Proxy) cleanup() {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Remove old messages from queue (TTL expired)
	cutoff := time.Now().Add(-p.config.Queue.MessageTTL)
	result, err := p.db.Exec("DELETE FROM queue WHERE created_at < ?", cutoff)
	if err != nil {
		logError("Failed to cleanup queue: %v", err)
	} else if n, _ := result.RowsAffected(); n > 0 {
		logInfo("Cleaned up %d expired messages from queue", n)
	}

	// Remove old entries from deduplication table
	dedupCutoff := time.Now().Add(-p.config.Deduplication.WindowTTL)
	result, err = p.db.Exec("DELETE FROM seen_updates WHERE seen_at < ?", dedupCutoff)
	if err != nil {
		logError("Failed to cleanup seen_updates: %v", err)
	} else if n, _ := result.RowsAffected(); n > 0 {
		logInfo("Cleaned up %d old deduplication entries", n)
	}
}

func (p *Proxy) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func (p *Proxy) handleStats(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()

	var total, pending, failed, dedup int
	p.db.QueryRow("SELECT COUNT(*) FROM queue").Scan(&total)
	p.db.QueryRow("SELECT COUNT(*) FROM queue WHERE attempts < ?", p.config.Queue.MaxRetries).Scan(&pending)
	p.db.QueryRow("SELECT COUNT(*) FROM queue WHERE attempts >= ?", p.config.Queue.MaxRetries).Scan(&failed)
	p.db.QueryRow("SELECT COUNT(*) FROM seen_updates").Scan(&dedup)

	stats := map[string]interface{}{
		"queued":              total,
		"pending":             pending,
		"failed":              failed,
		"dedup_window_size":   dedup,
		"backend_url":         p.config.Backend.URL,
		"max_retries":         p.config.Queue.MaxRetries,
		"message_ttl":         p.config.Queue.MessageTTL.String(),
		"deduplication":       p.config.Deduplication.Enabled,
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
