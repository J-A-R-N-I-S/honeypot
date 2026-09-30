package jarnis

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sampleConfig(name string) *Config {
	cfg := &Config{OK: true, HoneypotID: "hp_1", Name: name, UpdateIntervalSeconds: 120}
	cfg.Services.SSH.Banner = "hello\n"
	cfg.Services.HTTP.Designs = []Design{{ID: "d1", Name: "router", HTMLContent: "<h1>x</h1>"}}
	return cfg
}

func TestConfigCacheWriteReadPerms(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state") // does not exist yet
	path := filepath.Join(dir, "config.json")
	changed, err := SaveConfigCache(path, sampleConfig("a"))
	if err != nil || !changed {
		t.Fatalf("save changed=%v err=%v", changed, err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("cache mode %04o want 0600", fi.Mode().Perm())
	}
	di, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %04o want 0700", di.Mode().Perm())
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("temp file left behind: %v", ents)
	}
	got, err := LoadConfigCache(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "a" || got.HoneypotID != "" || len(got.Services.HTTP.Designs) != 1 || got.Services.SSH.Banner != "hello\n" {
		t.Fatalf("round trip %+v", got)
	}
}

func TestConfigCacheUnchangedIsNotRewritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if _, err := SaveConfigCache(path, sampleConfig("a")); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(path)
	changed, err := SaveConfigCache(path, sampleConfig("a"))
	if err != nil || changed {
		t.Fatalf("identical save changed=%v err=%v", changed, err)
	}
	after, _ := os.Stat(path)
	if !os.SameFile(before, after) {
		t.Fatal("identical config must not replace the file")
	}
	changed, err = SaveConfigCache(path, sampleConfig("b"))
	if err != nil || !changed {
		t.Fatalf("changed save changed=%v err=%v", changed, err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %04o after replace", fi.Mode().Perm())
	}
}

func TestConfigCacheLoadTightensLoosePerms(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"ok":true,"name":"x"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfigCache(path); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %04o want 0600", fi.Mode().Perm())
	}
}

func TestConfigCacheRejectsCorruptAndOversized(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(bad, []byte("{not json"), 0o600)
	if _, err := LoadConfigCache(bad); err == nil {
		t.Fatal("corrupt cache must fail")
	}
	big := filepath.Join(dir, "big.json")
	_ = os.WriteFile(big, []byte(`{"name":"`+strings.Repeat("a", maxConfigCacheBytes)+`"}`), 0o600)
	if _, err := LoadConfigCache(big); err == nil {
		t.Fatal("oversized cache must fail")
	}
	if _, err := LoadConfigCache(filepath.Join(dir, "missing.json")); !os.IsNotExist(err) {
		t.Fatalf("missing cache err=%v", err)
	}
}

// The cache holds only Config fields; the HONEYPOT_TOKEN is not one of them.
func TestConfigCacheHasNoToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if _, err := SaveConfigCache(path, sampleConfig("a")); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if strings.Contains(strings.ToLower(string(b)), "token") {
		t.Fatalf("cache must not contain a token field: %s", b)
	}
}

func TestConfigCacheRefusesSymlinkAndLeavesTargetAlone(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere")
	if err := os.WriteFile(target, []byte(`{"ok":true,"name":"x"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(target, 0o644)
	link := filepath.Join(dir, "config.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfigCache(link); err == nil {
		t.Fatal("symlinked cache must be refused")
	}
	if fi, _ := os.Stat(target); fi.Mode().Perm() != 0o644 {
		t.Fatalf("symlink target was chmodded to %04o", fi.Mode().Perm())
	}
	// Saving replaces the link itself, never writes through it.
	if _, err := SaveConfigCache(link, sampleConfig("new")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(target); string(b) != `{"ok":true,"name":"x"}` {
		t.Fatalf("wrote through the symlink: %s", b)
	}
	li, _ := os.Lstat(link)
	if li.Mode()&os.ModeSymlink != 0 || li.Mode().Perm() != 0o600 {
		t.Fatalf("cache is %v", li.Mode())
	}
}

func TestConfigCacheRefusesDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	_ = os.Mkdir(path, 0o700)
	if _, err := LoadConfigCache(path); err == nil {
		t.Fatal("directory must be refused")
	}
}
