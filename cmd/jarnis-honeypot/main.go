package main

import (
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/j-a-r-n-i-s/honeypot/internal/httpserv"
	"github.com/j-a-r-n-i-s/honeypot/internal/jarnis"
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

	sshPort := envInt("SSH_CONTAINER_PORT", 9022)
	telPort := envInt("TELNET_CONTAINER_PORT", 9023)
	httpPort := envInt("HTTP_CONTAINER_PORT", 9080)

	cli := jarnis.New("https://jarnis.io/api", "", token)
	q := queue.New(500)

	var mu sync.RWMutex
	var live jarnis.Config
	live.Services.SSH.Banner = "WARNING: This system is monitored.\n"
	live.Services.Telnet.Banner = live.Services.SSH.Banner
	interval := 300

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

	report := func(ev queue.Event) { q.Push(ev) }

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
				SourceIP: ev.SourceIP, SourcePort: ev.SourcePort, UserAgent: ev.UserAgent, SessionID: ev.SessionID,
				EventType: ev.EventType, Summary: ev.Summary, Raw: ev.Raw,
			}
			if err := cli.PostCredential(ce); err != nil {
				n, _ := q.Stats()
				log.Printf("backhaul: upload failed (%d events held): %v", n+1, err)
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
		}
	}()

	go func() {
		s := &sshserv.Server{Addr: ":" + strconv.Itoa(sshPort), KeyPath: "/var/lib/jarnis-honeypot/ssh_host_ecdsa", Banner: bannerSSH, Report: report}
		if err := s.ListenAndServe(); err != nil {
			log.Fatalf("ssh listen %s: %v", s.Addr, err)
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

	log.Printf("sensor up ports ssh=:%d telnet=:%d http=:%d", sshPort, telPort, httpPort)
	log.Printf("no interactive login is possible — credentials are captured and sent to JARNIS only")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Printf("shutdown")
}
