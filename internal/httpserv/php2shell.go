package httpserv

import (
	"bytes"
	"io"
	"mime"
	"net/http"
	"strings"
)

// php2shellField is the multipart form field name used by PHP session
// upload progress. A login decoy never emits it.
const php2shellField = "PHP_SESSION_UPLOAD_PROGRESS"

const postBodyLimit = 32 << 10

// readLimitedPost reads at most postBodyLimit and restores the body so
// later form parsing still works. The returned bytes are not stored.
func readLimitedPost(r *http.Request) []byte {
	if r == nil || r.Body == nil || r.Method != http.MethodPost {
		return nil
	}
	r.Body = http.MaxBytesReader(nil, r.Body, postBodyLimit)
	buf, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(buf))
	return buf
}

// php2shellAttempt reports a multipart POST that carries the upload-progress
// field name inside the already-read body prefix.
func php2shellAttempt(r *http.Request, body []byte) bool {
	if r == nil || r.Method != http.MethodPost || len(body) == 0 {
		return false
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(media, "multipart/form-data") {
		return false
	}
	return bytes.Contains(body, []byte(php2shellField))
}
