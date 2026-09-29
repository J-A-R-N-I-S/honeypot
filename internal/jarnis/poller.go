package jarnis

import (
	"context"
	"errors"
	"io/fs"
	"time"
)

// ConfigBackoff is the wait after the 1st, 2nd, 3rd, … consecutive failed
// config fetch; the last value repeats.
var ConfigBackoff = []time.Duration{5 * time.Second, 10 * time.Second, 30 * time.Second, 60 * time.Second}

// BackoffDelay returns the wait after `failures` consecutive failures (>= 1).
func BackoffDelay(failures int) time.Duration {
	if failures < 1 {
		failures = 1
	}
	if failures > len(ConfigBackoff) {
		return ConfigBackoff[len(ConfigBackoff)-1]
	}
	return ConfigBackoff[failures-1]
}

// Poller keeps the live config fresh: last good config from the cache at
// startup, then fetch with backoff until it works, then poll every interval.
type Poller struct {
	Fetch     func() (*Config, error)
	Apply     func(*Config)
	Interval  func() time.Duration // wait after a successful fetch
	CachePath string               // "" disables the cache

	// sleep is replaced in tests; it returns false when ctx is done.
	sleep func(ctx context.Context, d time.Duration) bool
}

// LoadCache applies the cached config, if any. Call it before opening the
// listeners so banners/designs are right from the first connection.
func (p *Poller) LoadCache() bool {
	if p.CachePath == "" {
		return false
	}
	cfg, err := LoadConfigCache(p.CachePath)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			Logf("config cache unusable: %v", err)
		}
		return false
	}
	p.Apply(cfg)
	Logf("config from cache %s name=%q designs=%d", p.CachePath, cfg.Name, len(cfg.Services.HTTP.Designs))
	return true
}

// Run fetches immediately and then forever until ctx is done. After a failed
// fetch it waits BackoffDelay(consecutive failures); after a success it
// applies and caches the config and waits Interval().
func (p *Poller) Run(ctx context.Context) {
	sleep := p.sleep
	if sleep == nil {
		sleep = sleepCtx
	}
	failures := 0
	everOK := false
	for {
		var wait time.Duration
		cfg, err := p.Fetch()
		if err != nil {
			failures++
			wait = BackoffDelay(failures)
			Logf("config fetch failed (attempt %d, retry in %s): %v", failures, wait, err)
		} else {
			if failures > 0 || !everOK {
				Logf("config ok name=%q designs=%d interval=%ds", cfg.Name, len(cfg.Services.HTTP.Designs), cfg.UpdateIntervalSeconds)
			}
			failures = 0
			everOK = true
			p.Apply(cfg)
			if p.CachePath != "" {
				if _, err := SaveConfigCache(p.CachePath, cfg); err != nil {
					Logf("config cache not written (%v) — mount a volume on /var/lib/jarnis-honeypot", err)
				}
			}
			wait = 30 * time.Second
			if p.Interval != nil {
				if iv := p.Interval(); iv >= 30*time.Second {
					wait = iv
				}
			}
		}
		if !sleep(ctx, wait) {
			return
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
