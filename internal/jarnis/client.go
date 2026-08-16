package jarnis

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client talks to the JARNIS control plane (config poll + credential backhaul).
type Client struct {
	API        string
	HoneypotID string
	Token      string
	HTTP       *http.Client
}

type ServiceSSH struct {
	Enabled       bool   `json:"enabled"`
	Port          int    `json:"port"`
	HostPort      int    `json:"hostPort"`
	ContainerPort int    `json:"containerPort"`
	Banner        string `json:"banner"`
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
	OK                    bool          `json:"ok"`
	HoneypotID            string        `json:"honeypotId"`
	Name                  string        `json:"name"`
	Status                string        `json:"status"`
	UpdateIntervalSeconds int           `json:"updateIntervalSeconds"`
	Services              struct {
		SSH    ServiceSSH    `json:"ssh"`
		Telnet ServiceTelnet `json:"telnet"`
		HTTP   ServiceHTTP   `json:"http"`
	} `json:"services"`
}

type CredEvent struct {
	HoneypotID string         `json:"honeypotId"`
	Service    string         `json:"service"`
	Username   string         `json:"username"`
	Password   string         `json:"password"`
	SourceIP   string         `json:"sourceIp"`
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

func New(api, honeypotID, token string) *Client {
	return &Client{
		API:        NormalizeAPI(api),
		HoneypotID: honeypotID,
		Token:      token,
		HTTP: &http.Client{
			Timeout: 20 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
	}
}

func (c *Client) FetchConfig() (*Config, error) {
	u, err := url.Parse(c.API + "/honeypots/config.php")
	if err != nil {
		return nil, err
	}
	q := u.Query()
	if c.HoneypotID != "" {
		q.Set("honeypotId", c.HoneypotID)
	}
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
	body, _ := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("config %d: %s", res.StatusCode, clip(body, 200))
	}
	var cfg Config
	if err := json.Unmarshal(body, &cfg); err != nil {
		return nil, err
	}
	if cfg.UpdateIntervalSeconds < 30 {
		cfg.UpdateIntervalSeconds = 30
	}
	return &cfg, nil
}

func (c *Client) PostCredential(ev CredEvent) error {
	ev.HoneypotID = c.HoneypotID
	if ev.EventType == "" {
		ev.EventType = "login_attempt"
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
	req.Header.Set("User-Agent", "jarnis-honeypot/0.1")
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
