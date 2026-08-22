package jarnis

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchAndPost(t *testing.T) {
	var got CredEvent
	var credAuth, credXHP string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/honeypots/config.php", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer hpt_testtoken_1234567890" {
			http.Error(w, "no", 401)
			return
		}
		_ = json.NewEncoder(w).Encode(Config{OK: true, HoneypotID: "hp_1", Name: "t", UpdateIntervalSeconds: 60})
	})
	mux.HandleFunc("/api/honeypots/credentials.php", func(w http.ResponseWriter, r *http.Request) {
		credAuth = r.Header.Get("Authorization")
		credXHP = r.Header.Get("X-Honeypot-Token")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	c := New(ts.URL+"/api", "hp_1", "hpt_testtoken_1234567890")
	cfg, err := c.FetchConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Name != "t" {
		t.Fatalf("cfg %+v", cfg)
	}
	if err := c.PostCredential(CredEvent{Service: "ssh", Username: "u", Password: "p", SourceIP: "1.2.3.4", SourcePort: 51234}); err != nil {
		t.Fatal(err)
	}
	if got.Username != "u" || got.HoneypotID != "hp_1" || got.Service != "ssh" || got.SourcePort != 51234 {
		t.Fatalf("posted %+v", got)
	}
	if got.Token != "hpt_testtoken_1234567890" {
		t.Fatalf("body token missing: %+v", got)
	}
	if credAuth != "Bearer hpt_testtoken_1234567890" || credXHP != "hpt_testtoken_1234567890" {
		t.Fatalf("headers auth=%q xhp=%q", credAuth, credXHP)
	}
}
