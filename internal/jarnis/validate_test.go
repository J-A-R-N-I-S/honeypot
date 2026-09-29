package jarnis

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseConfigRequiresOKAndID(t *testing.T) {
	bad := []string{
		`{}`,
		`{"ok":false,"honeypotId":"hp_1"}`,
		`{"ok":true}`,
		`{"ok":true,"honeypotId":"  "}`,
		`{"honeypotId":"hp_1","services":{"ssh":{"banner":""}}}`,
		`{"ok":true,"honeypotId":"hp_1","updateIntervalSeconds":"soon"}`,
	}
	for _, b := range bad {
		if _, err := parseConfig([]byte(b)); err == nil {
			t.Errorf("%s must be rejected", b)
		}
	}
	cfg, err := parseConfig([]byte(`{"ok":true,"honeypotId":"hp_1"}`))
	if err != nil || cfg.HoneypotID != "hp_1" || cfg.UpdateIntervalSeconds != 30 {
		t.Fatalf("%+v %v", cfg, err)
	}
}

func TestIntervalClamp(t *testing.T) {
	cases := map[string]IntervalSeconds{
		"999999999": 86400,
		"9.3e9":     86400,
		"1e400":     86400,
		"-1e400":    30,
		"86401":     86400,
		"86400":     86400,
		"-5":        30,
		"0":         30,
		"29":        30,
		"30":        30,
		"120.7":     120,
		"null":      30,
	}
	for in, want := range cases {
		cfg, err := parseConfig([]byte(`{"ok":true,"honeypotId":"hp_1","updateIntervalSeconds":` + in + `}`))
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		if cfg.UpdateIntervalSeconds != want {
			t.Errorf("%s -> %d want %d", in, cfg.UpdateIntervalSeconds, want)
		}
	}
}

// A 200 with {} or ok:false must neither be applied (it would clear the
// banners) nor overwrite the good cache.
func TestPollerIgnoresNotOKResponses(t *testing.T) {
	prev := discoverPublicIPv4
	discoverPublicIPv4 = func() string { return "" }
	t.Cleanup(func() { discoverPublicIPv4 = prev })

	for _, body := range []string{`{}`, `{"ok":false,"honeypotId":"hp_1"}`, `{"ok":true}`} {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(body))
		}))
		cache := filepath.Join(t.TempDir(), "config.json")
		if _, err := SaveConfigCache(cache, sampleConfig("good")); err != nil {
			t.Fatal(err)
		}
		before, _ := os.ReadFile(cache)
		cli := New(ts.URL+"/api", "", "hpt_x_1234567890123456789")
		applied := 0
		p := &Poller{Fetch: cli.FetchConfig, Apply: func(*Config) { applied++ }, SetIdentity: cli.SetHoneypotID, CachePath: cache}
		var slept time.Duration
		p.sleep = func(_ context.Context, d time.Duration) bool { slept = d; return false }
		p.jitter = noJitter
		p.Run(context.Background())
		ts.Close()
		after, _ := os.ReadFile(cache)
		if applied != 0 || string(before) != string(after) || cli.HoneypotID() != "" {
			t.Fatalf("%s: applied=%d cache changed=%v id=%q", body, applied, string(before) != string(after), cli.HoneypotID())
		}
		if slept != 5*time.Second {
			t.Fatalf("%s: must count as a failure (backoff), slept %v", body, slept)
		}
	}
}

func TestSaveConfigCacheRefusesNotOK(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if _, err := SaveConfigCache(path, &Config{}); err == nil {
		t.Fatal("must refuse")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("file written")
	}
}
