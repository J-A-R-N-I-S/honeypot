package jarnis

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Regression (review blocker): a state volume reused after re-registration
// holds a config.json from the OLD sensor. Its honeypotId must never be sent:
// the API answers a honeypotId that does not belong to the token with 403,
// which would lock the sensor out forever.
func TestStaleCachedHoneypotIDIsNeverSent(t *testing.T) {
	prev := discoverPublicIPv4
	discoverPublicIPv4 = func() string { return "" }
	t.Cleanup(func() { discoverPublicIPv4 = prev })

	const token = "hpt_new_token_after_reregistration_123"
	const liveID = "hp_new"
	var forbidden atomic.Int32
	var posted atomic.Int32
	mismatch := func(id string) bool { return id != "" && id != liveID }

	mux := http.NewServeMux()
	mux.HandleFunc("/api/honeypots/config.php", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		if mismatch(r.URL.Query().Get("honeypotId")) {
			forbidden.Add(1)
			http.Error(w, `{"ok":false,"error":"honeypot mismatch"}`, http.StatusForbidden)
			return
		}
		cfg := Config{OK: true, HoneypotID: liveID, Name: "live", UpdateIntervalSeconds: 60}
		_ = json.NewEncoder(w).Encode(cfg)
	})
	mux.HandleFunc("/api/honeypots/credentials.php", func(w http.ResponseWriter, r *http.Request) {
		var ev CredEvent
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &ev)
		if mismatch(ev.HoneypotID) {
			forbidden.Add(1)
			http.Error(w, "mismatch", http.StatusForbidden)
			return
		}
		posted.Add(1)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	// config.json left behind by the previous registration, including an
	// id (older format / hand-edited).
	cache := filepath.Join(t.TempDir(), "config.json")
	stale := `{"ok":true,"honeypotId":"hp_old","name":"old","updateIntervalSeconds":60,"services":{"ssh":{"banner":"cached banner\n"}}}`
	if err := os.WriteFile(cache, []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}

	cli := New(ts.URL+"/api", "", token)
	var applied []*Config
	p := &Poller{
		Fetch: cli.FetchConfig,
		// Even a consumer that naively adopts any id it is handed (the old
		// main.go did) must not get one from the cache.
		Apply: func(c *Config) {
			applied = append(applied, c)
			if c.HoneypotID != "" {
				cli.SetHoneypotID(c.HoneypotID)
			}
		},
		SetIdentity: cli.SetHoneypotID,
		CachePath:   cache,
	}
	if !p.LoadCache() {
		t.Fatal("cache not loaded")
	}
	if cli.HoneypotID() != "" {
		t.Fatalf("identity taken from cache: %q", cli.HoneypotID())
	}
	if applied[0].Services.SSH.Banner != "cached banner\n" || applied[0].HoneypotID != "" {
		t.Fatalf("cached config %+v", applied[0])
	}
	// Credential captured before the first live fetch: no id, no 403.
	if err := cli.PostCredential(CredEvent{Service: "ssh", Username: "u", Password: "p", SourceIP: "203.0.113.1"}); err != nil {
		t.Fatal(err)
	}

	p.sleep = func(context.Context, time.Duration) bool { return false } // one fetch
	p.Run(context.Background())

	if cli.HoneypotID() != liveID {
		t.Fatalf("identity %q want %q from the live fetch", cli.HoneypotID(), liveID)
	}
	if err := cli.PostCredential(CredEvent{Service: "ssh", Username: "u", Password: "p", SourceIP: "203.0.113.1"}); err != nil {
		t.Fatal(err)
	}
	if n := forbidden.Load(); n != 0 {
		t.Fatalf("API returned 403 %d times", n)
	}
	if posted.Load() != 2 {
		t.Fatalf("posted %d", posted.Load())
	}
	b, _ := os.ReadFile(cache)
	if strings.Contains(string(b), "hp_") {
		t.Fatalf("cache must not persist an identity: %s", b)
	}
}
