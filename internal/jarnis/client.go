package jarnis

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Version is the image/build id (ldflags). Old binaries stay "0.1".
var Version = "0.1"

// processStartedAt is this Go process start time (not Docker/host uptime).
var processStartedAt time.Time

func init() {
	processStartedAt = time.Now()
}

// ProcessUptimeSeconds is seconds since THIS Go process started.
// Never reads /proc/uptime.
func ProcessUptimeSeconds() int {
	if processStartedAt.IsZero() {
		processStartedAt = time.Now()
	}
	sec := int(time.Since(processStartedAt).Seconds())
	if sec < 0 {
		return 0
	}
	return sec
}

func AgentString() string {
	v := strings.TrimSpace(Version)
	if v == "" {
		v = "0.1"
	}
	return "jarnis-honeypot/" + v
}

// Client talks to the JARNIS control plane (config poll + credential backhaul).
type Client struct {
	API   string
	Token string
	HTTP  *http.Client

	idMu       sync.RWMutex
	honeypotID string
}

// HoneypotID is the sensor identity sent with every request ("" until the
// first successful live config fetch, unless set by the constructor).
func (c *Client) HoneypotID() string {
	c.idMu.RLock()
	defer c.idMu.RUnlock()
	return c.honeypotID
}

// SetHoneypotID updates the identity. Only call it with the honeypotId of a
// live, validated config response — never with a cached value: the API
// rejects (403) a honeypotId that does not belong to the token.
func (c *Client) SetHoneypotID(id string) {
	c.idMu.Lock()
	c.honeypotID = id
	c.idMu.Unlock()
}

type ServiceSSH struct {
	Enabled       bool   `json:"enabled"`
	Port          int    `json:"port"`
	HostPort      int    `json:"hostPort"`
	ContainerPort int    `json:"containerPort"`
	Banner        string `json:"banner"`
	// ServerVersion optionally overrides the SSH identification string
	// ("SSH-2.0-…"). The SSH_SERVER_VERSION env var takes precedence.
	ServerVersion string `json:"serverVersion,omitempty"`
}

type ServiceTelnet struct {
	Enabled       bool   `json:"enabled"`
	Port          int    `json:"port"`
	HostPort      int    `json:"hostPort"`
	ContainerPort int    `json:"containerPort"`
	Banner        string `json:"banner"`
}

type Design struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	HTMLContent string `json:"htmlContent"`
	CSSContent  string `json:"cssContent"`
}

type ServiceHTTP struct {
	Enabled       bool     `json:"enabled"`
	Port          int      `json:"port"`
	HostPort      int      `json:"hostPort"`
	ContainerPort int      `json:"containerPort"`
	RotationMode  string   `json:"rotationMode"`
	Designs       []Design `json:"designs"`
}

type Config struct {
	OK                    bool   `json:"ok"`
	HoneypotID            string `json:"honeypotId"`
	Name                  string `json:"name"`
	Status                string `json:"status"`
	UpdateIntervalSeconds IntervalSeconds `json:"updateIntervalSeconds"`
	Services              struct {
		SSH    ServiceSSH    `json:"ssh"`
		Telnet ServiceTelnet `json:"telnet"`
		HTTP   ServiceHTTP   `json:"http"`
	} `json:"services"`
}

type CredEvent struct {
	HoneypotID string         `json:"honeypotId"`
	Token      string         `json:"token,omitempty"`
	Service    string         `json:"service"`
	Username   string         `json:"username"`
	Password   string         `json:"password"`
	SourceIP   string         `json:"sourceIp"`
	SourcePort int            `json:"sourcePort,omitempty"`
	PublicIP   string         `json:"publicIp,omitempty"`
	UserAgent  string         `json:"userAgent,omitempty"`
	SessionID  string         `json:"sessionId,omitempty"`
	EventType  string         `json:"eventType"`
	Summary    string         `json:"summary,omitempty"`
	Raw        map[string]any `json:"raw,omitempty"`
}

func NormalizeAPI(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.TrimRight(s, "/")
	if s == "" {
		return "https://jarnis.io/api"
	}
	if strings.HasSuffix(s, "/api") {
		return s
	}
	// Accept origin-only values from operators.
	if !strings.Contains(s, "/api/") && !strings.HasSuffix(s, "/api") {
		return s + "/api"
	}
	return s
}

// DefaultAPIFallbackIP is dialed for the API host (jarnis.io) only when the
// normal DNS-based connect fails, e.g. on networks whose firewall blocks
// public DNS resolvers. TLS is still verified against the host name, so a
// wrong or stale IP can only make the fallback fail, never impersonate the
// API. Override or disable with JARNIS_API_FALLBACK_IP.
const DefaultAPIFallbackIP = "116.204.196.220"

// Options tune the control-plane client.
type Options struct {
	// FallbackIP is dialed for the API host when resolving or connecting to
	// it by name fails. "" disables the fallback.
	FallbackIP string
}

// New returns a client with the default options (DNS first, fallback IP
// DefaultAPIFallbackIP).
func New(api, honeypotID, token string) *Client {
	return NewWithOptions(api, honeypotID, token, Options{FallbackIP: DefaultAPIFallbackIP})
}

func NewWithOptions(api, honeypotID, token string, opt Options) *Client {
	base := NormalizeAPI(api)
	u, _ := url.Parse(base)
	sni := "jarnis.io"
	apiHost := ""
	if u != nil && u.Hostname() != "" && net.ParseIP(u.Hostname()) == nil {
		sni = u.Hostname()
		apiHost = u.Hostname()
	}
	fd := &fallbackDialer{
		Host:       apiHost,
		FallbackIP: opt.FallbackIP,
		Dial:       (&net.Dialer{Timeout: 7 * time.Second}).DialContext,
	}
	tr := &http.Transport{
		Proxy:               nil,
		DialContext:         fd.DialContext,
		TLSClientConfig:     &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	return &Client{
		API:        base,
		honeypotID: honeypotID,
		Token:      token,
		HTTP: &http.Client{
			Timeout:   20 * time.Second,
			Transport: tr,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return fmt.Errorf("redirects disabled")
			},
		},
	}
}

// fallbackDialer connects by name (normal DNS) and, for the API host only,
// retries on FallbackIP when that fails.
type fallbackDialer struct {
	Host       string // API host name; "" = never fall back
	FallbackIP string
	Dial       func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (d *fallbackDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		host, port = addr, "443"
	}
	target := net.JoinHostPort(host, port)
	conn, err := d.Dial(ctx, "tcp", target)
	if err == nil {
		return conn, nil
	}
	if d.FallbackIP == "" || d.Host == "" || !strings.EqualFold(host, d.Host) || ctx.Err() != nil {
		return nil, err
	}
	conn, ferr := d.Dial(ctx, "tcp", net.JoinHostPort(d.FallbackIP, port))
	if ferr != nil {
		return nil, fmt.Errorf("%w; fallback %s: %v", err, d.FallbackIP, ferr)
	}
	return conn, nil
}

func (c *Client) FetchConfig() (*Config, error) {
	u, err := url.Parse(c.API + "/honeypots/config.php")
	if err != nil {
		return nil, err
	}
	q := u.Query()
	if id := c.HoneypotID(); id != "" {
		q.Set("honeypotId", id)
	}
	// Refresh egress IP on each config poll; best-effort, never fails the request.
	if ip := refreshPublicIP(); ip != "" {
		q.Set("publicIp", ip)
	}
	q.Set("uptimeSeconds", strconv.Itoa(ProcessUptimeSeconds()))
	u.RawQuery = q.Encode()
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	c.auth(req)
	res, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 2<<20))
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("config %d: %s", res.StatusCode, clip(body, 200))
	}
	return parseConfig(body)
}

// parseConfig decodes and validates a config response. Only a response with
// ok:true and a honeypotId is usable; anything else ({} or ok:false with
// status 200) is an error, so it neither replaces the live config (and
// clears the banners) nor overwrites a good cache.
func parseConfig(body []byte) (*Config, error) {
	var cfg Config
	if err := json.Unmarshal(body, &cfg); err != nil {
		return nil, err
	}
	if !cfg.OK {
		return nil, fmt.Errorf("config rejected: ok=false: %s", clip(body, 200))
	}
	if strings.TrimSpace(cfg.HoneypotID) == "" {
		return nil, fmt.Errorf("config rejected: no honeypotId")
	}
	cfg.UpdateIntervalSeconds = cfg.UpdateIntervalSeconds.Clamp()
	return &cfg, nil
}

const (
	MinUpdateIntervalSeconds = 30
	MaxUpdateIntervalSeconds = 86400
)

// IntervalSeconds is the poll interval. It accepts any JSON number (also
// 9.3e9 or 120.5) without failing the whole config and saturates instead of
// overflowing; Clamp limits it to 30..86400.
type IntervalSeconds int

func (s *IntervalSeconds) UnmarshalJSON(b []byte) error {
	v := strings.TrimSpace(string(b))
	if v == "null" {
		*s = 0
		return nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if ne, ok := err.(*strconv.NumError); ok && ne.Err == strconv.ErrRange {
		err = nil // ±Inf: saturate below
	}
	if err != nil || math.IsNaN(f) {
		return fmt.Errorf("updateIntervalSeconds: not a number: %s", clip(b, 40))
	}
	switch {
	case f > math.MaxInt32:
		*s = math.MaxInt32
	case f < math.MinInt32:
		*s = math.MinInt32
	default:
		*s = IntervalSeconds(f)
	}
	return nil
}

// Clamp returns the interval limited to MinUpdateIntervalSeconds ..
// MaxUpdateIntervalSeconds (0 and negative values give the minimum).
func (s IntervalSeconds) Clamp() IntervalSeconds {
	if s < MinUpdateIntervalSeconds {
		return MinUpdateIntervalSeconds
	}
	if s > MaxUpdateIntervalSeconds {
		return MaxUpdateIntervalSeconds
	}
	return s
}

func (c *Client) PostCredential(ev CredEvent) error {
	ev.HoneypotID = c.HoneypotID()
	// Body token survives proxies that strip Authorization on POST.
	ev.Token = c.Token
	if ev.EventType == "" {
		ev.EventType = "login_attempt"
	}
	if ev.PublicIP == "" {
		if ip := getCachedPublicIP(); ip != "" {
			ev.PublicIP = ip
		} else if ip := refreshPublicIP(); ip != "" {
			ev.PublicIP = ip
		}
	}
	payload, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, c.API+"/honeypots/credentials.php", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	c.auth(req)
	req.Header.Set("Content-Type", "application/json")
	res, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode >= 300 {
		return fmt.Errorf("credentials %d: %s", res.StatusCode, clip(body, 200))
	}
	return nil
}

func (c *Client) auth(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("X-Honeypot-Token", c.Token)
	req.Header.Set("User-Agent", AgentString())
	req.Header.Set("X-Jarnis-Agent", AgentString())
}

func clip(b []byte, n int) string {
	s := strings.TrimSpace(string(b))
	if len(s) > n {
		return s[:n]
	}
	return s
}

func Logf(format string, args ...any) {
	log.Printf(format, args...)
}
