package jarnis

import (
	"context"
	"errors"
	"io/fs"
	"math/rand/v2"
	"time"
)

// ConfigBackoff is the wait after the 1st, 2nd, 3rd, … consecutive failed
// config fetch; the last value repeats.
var ConfigBackoff = []time.Duration{5 * time.Second, 10 * time.Second, 30 * time.Second, 60 * time.Second}

// AuthRetryDelay is the wait after the API rejected the token (401/403):
// not transient, so do not hammer the API every 60 s.
var AuthRetryDelay = 15 * time.Minute

// JitterFraction: every wait is randomised by ±20 % so sensors that lost the
// API at the same moment do not come back in lockstep.
const JitterFraction = 0.2

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
	Fetch func() (*Config, error)
	// Apply installs a config for the listeners (banners, designs, interval).
	// Cached configs never carry a honeypotId.
	Apply func(*Config)
	// SetIdentity receives the honeypotId of each successful LIVE fetch only.
	SetIdentity func(id string)
	Interval    func() time.Duration // wait after a successful fetch
	CachePath   string               // "" disables the cache

	// sleep is replaced in tests; it returns false when ctx is done.
	sleep func(ctx context.Context, d time.Duration) bool
	// jitter is replaced in tests (nil = randomJitter).
	jitter func(time.Duration) time.Duration
}

func randomJitter(d time.Duration) time.Duration {
	f := 1 - JitterFraction + 2*JitterFraction*rand.Float64()
	return time.Duration(float64(d) * f)
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
// fetch it waits BackoffDelay(consecutive failures), after a 401/403
// AuthRetryDelay; after a success it applies and caches the config and waits
// Interval(). Every wait gets ±20 % jitter.
func (p *Poller) Run(ctx context.Context) {
	sleep := p.sleep
	if sleep == nil {
		sleep = sleepCtx
	}
	jitter := p.jitter
	if jitter == nil {
		jitter = randomJitter
	}
	failures := 0
	everOK := false
	for {
		var wait time.Duration
		cfg, err := p.Fetch()
		switch {
		case err != nil && IsAuthError(err):
			failures++
			wait = jitter(AuthRetryDelay)
			Logf("config fetch: JARNIS rejected HONEYPOT_TOKEN (%v) — check the token in the app (Honeypots → rotate) and recreate the container; retrying in %s", err, wait.Round(time.Second))
		case err != nil:
			failures++
			wait = jitter(BackoffDelay(failures))
			Logf("config fetch failed (attempt %d, retry in %s): %v", failures, wait.Round(time.Second), err)
		default:
			if failures > 0 || !everOK {
				Logf("config ok name=%q designs=%d interval=%ds", cfg.Name, len(cfg.Services.HTTP.Designs), cfg.UpdateIntervalSeconds)
			}
			failures = 0
			everOK = true
			if p.SetIdentity != nil && cfg.HoneypotID != "" {
				p.SetIdentity(cfg.HoneypotID)
			}
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
			wait = jitter(wait)
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
