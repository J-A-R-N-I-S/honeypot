package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"sync"
)

// Tiny control-plane stand-in for local smoke tests.
func main() {
	var mu sync.Mutex
	var hits []map[string]any
	mux := http.NewServeMux()
	mux.HandleFunc("/api/honeypots/config.php", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"honeypotId":"hp_local","name":"Local","status":"pending","updateIntervalSeconds":30,"services":{"ssh":{"enabled":true,"banner":"LOCAL SSH HONEYPOT\n"},"telnet":{"enabled":true,"banner":"LOCAL TELNET HONEYPOT\n"},"http":{"enabled":true,"rotationMode":"sticky-per-ip","designs":[]}}}`))
	})
	mux.HandleFunc("/api/honeypots/credentials.php", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		mu.Lock()
		hits = append(hits, m)
		n := len(hits)
		mu.Unlock()
		os.Stderr.WriteString("HIT " + string(b) + "\n")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"n":` + itoa(n) + `}`))
	})
	addr := ":18080"
	if v := os.Getenv("ADDR"); v != "" {
		addr = v
	}
	println("mock api", addr)
	_ = http.ListenAndServe(addr, mux)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [16]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
