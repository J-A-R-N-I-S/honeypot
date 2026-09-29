package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/j-a-r-n-i-s/honeypot/internal/httpserv"
	"github.com/j-a-r-n-i-s/honeypot/internal/jarnis"
	"github.com/j-a-r-n-i-s/honeypot/internal/probe"
	"github.com/j-a-r-n-i-s/honeypot/internal/queue"
	"github.com/j-a-r-n-i-s/honeypot/internal/sshserv"
	"github.com/j-a-r-n-i-s/honeypot/internal/telserv"
)

func envInt(k string, def int) int {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 || n > 65535 {
		return def
	}
	return n
}

func tokenFromEnv() string {
	t := strings.TrimSpace(os.Getenv("HONEYPOT_TOKEN"))
	return strings.Trim(t, `"'`)
}

func validToken(t string) bool {
	return len(t) >= 20 && t != "${HONEYPOT_TOKEN}"
}

// fallbackIPFromEnv reads JARNIS_API_FALLBACK_IP: unset/empty = default,
// "off"/"none" = disabled, otherwise an IP literal.
func fallbackIPFromEnv() string {
	v := strings.TrimSpace(os.Getenv("JARNIS_API_FALLBACK_IP"))
	switch strings.ToLower(v) {
	case "":
		return jarnis.DefaultAPIFallbackIP
	case "off", "none":
		return ""
	}
	if net.ParseIP(v) == nil {
		log.Printf("ignoring invalid JARNIS_API_FALLBACK_IP %q — using %s", v, jarnis.DefaultAPIFallbackIP)
		return jarnis.DefaultAPIFallbackIP
	}
	return v
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("jarnis-hp ")

	token := tokenFromEnv()
	if !validToken(token) {
		log.Printf("waiting for HONEYPOT_TOKEN (env only — not the start command)")
		for {
			time.Sleep(15 * time.Second)
			token = tokenFromEnv()
			if validToken(token) {
				break
			}
		}
	}

	sshPort := envInt("SSH_CONTAINER_PORT", 22)
	telPort := envInt("TELNET_CONTAINER_PORT", 23)
	httpPort := envInt("HTTP_CONTAINER_PORT", 8080)

	cli := jarnis.NewWithOptions("https://jarnis.io/api", "", token, jarnis.Options{FallbackIP: fallbackIPFromEnv()})
	q := queue.New(500)

	var mu sync.RWMutex
	var live jarnis.Config
	live.Services.SSH.Banner = "WARNING: This system is monitored.\n"
	live.Services.Telnet.Banner = live.Services.SSH.Banner
	interval := 300

	// SSH identification string: SSH_SERVER_VERSION > config
	// services.ssh.serverVersion > per-install default from the host key.
	sshVersionEnv := strings.TrimSpace(os.Getenv("SSH_SERVER_VERSION"))
	if sshVersionEnv != "" && !sshserv.ValidVersion(sshVersionEnv) {
		log.Printf("ignoring invalid SSH_SERVER_VERSION %q (want e.g. %q)", sshVersionEnv, sshserv.DefaultVersion)
		sshVersionEnv = ""
	}

	apply := func(cfg *jarnis.Config) {
		mu.Lock()
		defer mu.Unlock()
		if v := cfg.Services.SSH.ServerVersion; v != "" && !sshserv.ValidVersion(v) {
			log.Printf("ignoring invalid config services.ssh.serverVersion %q", v)
		}
		live = *cfg
		if cfg.UpdateIntervalSeconds >= 30 {
			interval = cfg.UpdateIntervalSeconds
		}
		// Identity is NOT taken from here: see Poller.SetIdentity.
	}
	bannerSSH := func() string {
		mu.RLock()
		defer mu.RUnlock()
		return live.Services.SSH.Banner
	}
	bannerTel := func() string {
		mu.RLock()
		defer mu.RUnlock()
		return live.Services.Telnet.Banner
	}
	sshVersion := func() string {
		if sshVersionEnv != "" {
			return sshVersionEnv
		}
		mu.RLock()
		defer mu.RUnlock()
		return live.Services.SSH.ServerVersion
	}
	designs := func() []jarnis.Design {
		mu.RLock()
		defer mu.RUnlock()
		return live.Services.HTTP.Designs
	}
	mode := func() string {
		mu.RLock()
		defer mu.RUnlock()
		return live.Services.HTTP.RotationMode
	}

	tracker := probe.New()
	report := tracker.Report(func(ev queue.Event) { q.Push(ev) })

	cachePath := strings.TrimSpace(os.Getenv("CONFIG_CACHE_PATH"))
	switch strings.ToLower(cachePath) {
	case "":
		cachePath = jarnis.DefaultConfigCachePath
	case "off", "none":
		cachePath = ""
	}
	poller := &jarnis.Poller{
		Fetch:       cli.FetchConfig,
		Apply:       apply,
		SetIdentity: cli.SetHoneypotID,
		CachePath:   cachePath,
		Interval: func() time.Duration {
			mu.RLock()
			defer mu.RUnlock()
			return time.Duration(interval) * time.Second
		},
	}
	// Last good config first (banners, designs — never the honeypot ID), so
	// the listeners have the right look even when the API is unreachable.
	poller.LoadCache()

	// Open every port BEFORE talking to the API: a slow or unreachable
	// control plane must never keep the decoy offline.
	sshSrv := &sshserv.Server{Addr: ":" + strconv.Itoa(sshPort), KeyPath: "/var/lib/jarnis-honeypot/ssh_host_ecdsa", Banner: bannerSSH, Version: sshVersion, Report: report}
	if err := sshSrv.Listen(); err != nil {
		log.Fatalf("ssh listen %s: %v", sshSrv.Addr, err)
	}
	telSrv := &telserv.Server{Addr: ":" + strconv.Itoa(telPort), Banner: bannerTel, Report: report}
	if err := telSrv.Listen(); err != nil {
		log.Fatalf("telnet listen %s: %v", telSrv.Addr, err)
	}
	httpSrv := &httpserv.Server{Addr: ":" + strconv.Itoa(httpPort), Designs: designs, Mode: mode, Report: report}
	if err := httpSrv.Listen(); err != nil {
		log.Fatalf("http listen %s: %v", httpSrv.Addr, err)
	}
	go func() { log.Fatalf("ssh: %v", sshSrv.Serve()) }()
	go func() { log.Fatalf("telnet: %v", telSrv.Serve()) }()
	go func() { log.Fatalf("http: %v", httpSrv.Serve()) }()

	log.Printf("sensor up ports ssh=:%d telnet=:%d http=:%d", sshPort, telPort, httpPort)
	log.Printf("no interactive login is possible — credentials are captured and sent to JARNIS only")

	// Config: fetch now, retry with backoff 5s/10s/30s/60s/60s…, then poll.
	go poller.Run(context.Background())

	go func() {
		for {
			ev, ok := q.PopReady(time.Now())
			if !ok {
				time.Sleep(400 * time.Millisecond)
				continue
			}
			ce := jarnis.CredEvent{
				Service: ev.Service, Username: ev.Username, Password: ev.Password,
				SourceIP: ev.SourceIP, SourcePort: ev.SourcePort, UserAgent: ev.UserAgent, SessionID: ev.SessionID,
				EventType: ev.EventType, Summary: ev.Summary, Raw: ev.Raw,
			}
			if err := cli.PostCredential(ce); err != nil {
				log.Printf("backhaul retry: %v", err)
				q.Retry(ev, time.Duration(2+ev.Tries)*time.Second)
			}
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Printf("shutdown")
}
