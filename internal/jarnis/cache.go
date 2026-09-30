package jarnis

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// DefaultConfigCachePath is where the last good remote config is kept. It is
// on the state volume (/var/lib/jarnis-honeypot) together with the SSH host
// key, so it survives restarts and recreates.
const DefaultConfigCachePath = "/var/lib/jarnis-honeypot/config.json"

const maxConfigCacheBytes = 2 << 20 // same limit as the config fetch

// SaveConfigCache writes cfg to path atomically (temp file in the same
// directory, fsync, rename, fsync dir) with mode 0600; the directory is
// created with mode 0700 if missing. Only the fields of Config are written —
// never the HONEYPOT_TOKEN, which is not part of Config — and the honeypotId
// is blanked: identity always comes from a live fetch (a volume reused with
// a new token must not pin the old id, which the API answers with 403).
// It returns changed=false (and does not touch the file) when the content
// is identical.
func SaveConfigCache(path string, cfg *Config) (changed bool, err error) {
	if cfg == nil || !cfg.OK {
		return false, fmt.Errorf("refusing to cache a config without ok=true")
	}
	c := *cfg
	c.HoneypotID = ""
	data, err := json.Marshal(&c)
	if err != nil {
		return false, err
	}
	if f, fi, err := openCacheFile(path); err == nil {
		old, rerr := io.ReadAll(io.LimitReader(f, maxConfigCacheBytes+1))
		if rerr == nil && bytes.Equal(old, data) {
			// Unchanged: keep the file, but still enforce 0600.
			if fi.Mode().Perm() != 0o600 {
				_ = f.Chmod(0o600)
			}
			_ = f.Close()
			return false, nil
		}
		_ = f.Close()
	}
	// A symlink or other non-regular file at path is replaced by the rename
	// (rename does not follow symlinks), never written through.
	if err := writeFileAtomic(path, data, 0o600); err != nil {
		return false, err
	}
	return true, nil
}

// LoadConfigCache reads a config written by SaveConfigCache. A cache file
// readable by group/other is tightened to 0600 (best effort).
func LoadConfigCache(path string) (*Config, error) {
	f, fi, err := openCacheFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi.Mode().Perm()&0o077 != 0 {
		Logf("config cache %s has mode %04o — tightening to 0600", path, fi.Mode().Perm())
		_ = f.Chmod(0o600)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxConfigCacheBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxConfigCacheBytes {
		return nil, fmt.Errorf("config cache %s larger than %d bytes", path, maxConfigCacheBytes)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config cache %s: %w", path, err)
	}
	// Never trust an identity from disk (older files may still carry one).
	cfg.HoneypotID = ""
	if !cfg.OK {
		return nil, fmt.Errorf("config cache %s: ok is not true", path)
	}
	cfg.UpdateIntervalSeconds = cfg.UpdateIntervalSeconds.Clamp()
	return &cfg, nil
}

// openCacheFile opens path read-only only if it is a regular file: Lstat
// refuses symlinks (whose target would otherwise be read and chmodded) and
// FIFOs/devices (which would block startup); O_NOFOLLOW|O_NONBLOCK and a
// SameFile check close the race between Lstat and open.
func openCacheFile(path string) (*os.File, os.FileInfo, error) {
	li, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if li.Mode()&os.ModeSymlink != 0 {
		return nil, nil, fmt.Errorf("config cache %s is a symlink — refusing", path)
	}
	if !li.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("config cache %s is not a regular file (%s) — refusing", path, li.Mode().Type())
	}
	f, err := os.OpenFile(path, os.O_RDONLY|openFlagsNoFollow, 0)
	if err != nil {
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() || !os.SameFile(li, fi) {
		_ = f.Close()
		return nil, nil, fmt.Errorf("config cache %s changed while opening — refusing", path)
	}
	return f, fi, nil
}

// writeFileAtomic writes data to a temp file in the target directory, fsyncs
// it, renames it over path and fsyncs the directory, so a crash never leaves
// a truncated file behind. The directory is created 0700 if missing.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(perm); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
