package httpserv

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"mime"
	"net/http"
	"net/url"
	"strings"
)

// Node2Shell probes target Node.js / Next.js stacks (CVE-2026-111497 Brotli
// out-of-bounds, React Server Components actions, prototype pollution, RCE
// payloads). Detection only looks at the already-read 32 KiB body prefix and
// headers. The body is NEVER decompressed or decoded: a Brotli body is only
// measured (length + sha256 prefix), never inflated.
//
// Precedence: php2shell (more specific multipart marker) wins over node2shell;
// within node2shell the first match in this order wins:
// brotli, rce, proto, rsc, probe.

const (
	n2sBrotli = "brotli"
	n2sRSC    = "rsc"
	n2sProto  = "proto"
	n2sRCE    = "rce"
	n2sProbe  = "probe"
)

var (
	n2sRSCBody   = [][]byte{[]byte("$ACTION_"), []byte(`"$@`), []byte(`"then":"$`)}
	n2sProtoMark = []string{"__proto__", "constructor[prototype]", "constructor.prototype"}
	n2sRCEMark   = [][]byte{[]byte("child_process"), []byte("require("), []byte("process.mainModule"), []byte("execSync")}
	n2sProbePath = []string{"/_next/", "/__nextjs_original-stack-frame"}
)

// contentEncodingHasBr reports whether any Content-Encoding token is "br".
func contentEncodingHasBr(r *http.Request) bool {
	for _, v := range r.Header.Values("Content-Encoding") {
		for _, tok := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "br") {
				return true
			}
		}
	}
	return false
}

// node2shellAttempt returns the probe kind or "" if nothing matched.
func node2shellAttempt(r *http.Request, body []byte) string {
	if r == nil {
		return ""
	}
	if (r.Method == http.MethodPost || r.Method == http.MethodPut) && len(body) > 0 && contentEncodingHasBr(r) {
		return n2sBrotli
	}
	query := r.URL.RawQuery
	if uq, err := url.QueryUnescape(query); err == nil {
		query = uq
	}
	for _, m := range n2sRCEMark {
		if bytes.Contains(body, m) || strings.Contains(query, string(m)) {
			return n2sRCE
		}
	}
	for _, m := range n2sProtoMark {
		if strings.Contains(query, m) || bytes.Contains(body, []byte(m)) {
			return n2sProto
		}
	}
	if r.Header.Get("Next-Action") != "" || r.Header.Get("Next-Router-State-Tree") != "" ||
		strings.TrimSpace(r.Header.Get("RSC")) == "1" {
		return n2sRSC
	}
	if media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err == nil && strings.EqualFold(media, "text/x-component") {
		return n2sRSC
	}
	for _, m := range n2sRSCBody {
		if bytes.Contains(body, m) {
			return n2sRSC
		}
	}
	for _, p := range n2sProbePath {
		if strings.HasPrefix(r.URL.Path, p) {
			return n2sProbe
		}
	}
	return ""
}

// node2shellFields adds metadata for the report. Only measures the body.
func node2shellFields(raw map[string]any, r *http.Request, kind string, body []byte) {
	raw["attack"] = "node2shell"
	raw["attack_kind"] = kind
	if kind == n2sBrotli {
		sum := sha256.Sum256(body)
		raw["content_encoding"] = clip(strings.Join(r.Header.Values("Content-Encoding"), ", "), 100)
		raw["content_type"] = clip(r.Header.Get("Content-Type"), 100)
		raw["body_len"] = len(body)
		raw["body_sha256_prefix"] = hex.EncodeToString(sum[:8])
	}
}
