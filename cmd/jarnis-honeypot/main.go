package main

import (
	"log"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/jarnis/honeypot/internal/httpserv"
	"github.com/jarnis/honeypot/internal/jarnis"
	"github.com/jarnis/honeypot/internal/queue"
	"github.com/jarnis/honeypot/internal/sshserv"
	"github.com/jarnis/honeypot/internal/telserv"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

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

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("jarnis-hp ")

	hpID := os.Getenv("HONEYPOT_ID")
	token := os.Getenv("HONEYPOT_TOKEN")
	api := env("JARNIS_API", "https://jarnis.io/api")
	if token == "" {
		log.Fatal("HONEYPOT_TOKEN is required (full hpt_… from create/rotate). HONEYPOT_ID is optional — the token already selects the honeypot.")
	}
	if len(token) < 20 || token == "${HONEYPOT_TOKEN}" {
		log.Fatal("HONEYPOT_TOKEN looks empty or is still the placeholder — rotate the token in the app and paste the full hpt_… secret")
	}

	sshPort := envInt("SSH_CONTAINER_PORT", 22)
	telPort := envInt("TELNET_CONTAINER_PORT", 23)
	httpPort := envInt("HTTP_CONTAINER_PORT", 80)
	interval := envInt("UPDATE_INTERVAL", 300)
	if interval < 30 {
		interval = 30
	}
	keyPath := env("SSH_HOST_KEY", "/var/lib/jarnis-honeypot/ssh_host_ecdsa")

	cli := jarnis.New(api, hpID, token)
	q := queue.New(500)

	var mu sync.RWMutex
	var live jarnis.Config
	live.Services.SSH.Banner = "WARNING: This system is monitored.\n"
	live.Services.Telnet.Banner = live.Services.SSH.Banner
	live.UpdateIntervalSeconds = interval

	apply := func(cfg *jarnis.Config) {
		mu.Lock()
		defer mu.Unlock()
		live = *cfg
		if cfg.UpdateIntervalSeconds >= 30 {
			interval = cfg.UpdateIntervalSeconds
		}
		if cfg.HoneypotID != "" {
			cli.HoneypotID = cfg.HoneypotID
		}
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

	report := func(ev queue.Event) {
		q.Push(ev)
	}

	// First config fetch — banners/designs. Failure is OK; keep serving defaults.
	if cfg, err := cli.FetchConfig(); err != nil {
		log.Printf("config fetch failed (will retry): %v", err)
	} else {
		apply(cfg)
		log.Printf("config ok name=%q designs=%d interval=%ds", cfg.Name, len(cfg.Services.HTTP.Designs), cfg.UpdateIntervalSeconds)
	}

	go func() {
		for {
			ev, ok := q.PopReady(time.Now())
			if !ok {
				time.Sleep(400 * time.Millisecond)
				continue
			}
			ce := jarnis.CredEvent{
				Service: ev.Service, Username: ev.Username, Password: ev.Password,
				SourceIP: ev.SourceIP, UserAgent: ev.UserAgent, SessionID: ev.SessionID,
				EventType: ev.EventType, Summary: ev.Summary, Raw: ev.Raw,
			}
			if err := cli.PostCredential(ce); err != nil {
				log.Printf("backhaul retry: %v", err)
				q.Retry(ev, time.Duration(2+ev.Tries)*time.Second)
			}
		}
	}()

	go func() {
		for {
			mu.RLock()
			wait := interval
			mu.RUnlock()
			if wait < 30 {
				wait = 30
			}
			time.Sleep(time.Duration(wait) * time.Second)
			cfg, err := cli.FetchConfig()
			if err != nil {
				log.Printf("config poll: %v", err)
				continue
			}
			apply(cfg)
			log.Printf("config refreshed designs=%d interval=%ds", len(cfg.Services.HTTP.Designs), cfg.UpdateIntervalSeconds)
		}
	}()

	go func() {
		s := &sshserv.Server{Addr: ":" + strconv.Itoa(sshPort), KeyPath: keyPath, Banner: bannerSSH, Report: report}
		if err := s.ListenAndServe(); err != nil {
			log.Fatalf("ssh: %v", err)
		}
	}()
	go func() {
		s := &telserv.Server{Addr: ":" + strconv.Itoa(telPort), Banner: bannerTel, Report: report}
		if err := s.ListenAndServe(); err != nil {
			log.Fatalf("telnet: %v", err)
		}
	}()
	go func() {
		s := &httpserv.Server{Addr: ":" + strconv.Itoa(httpPort), Designs: designs, Mode: mode, Report: report}
		if err := s.ListenAndServe(); err != nil {
			log.Fatalf("http: %v", err)
		}
	}()

	log.Printf("sensor up id=%s api=%s ports ssh=:%d telnet=:%d http=:%d", cli.HoneypotID, cli.API, sshPort, telPort, httpPort)
	log.Printf("no interactive login is possible — credentials are captured and sent to JARNIS only")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Printf("shutdown")
}
