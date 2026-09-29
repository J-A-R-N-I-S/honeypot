//go:build unix

package jarnis

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestConfigCacheRefusesFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := LoadConfigCache(path)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO must be refused")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("LoadConfigCache blocked on a FIFO")
	}
	if _, err := SaveConfigCache(path, sampleConfig("a")); err != nil {
		t.Fatalf("save over FIFO: %v", err)
	}
	if fi, _ := os.Lstat(path); !fi.Mode().IsRegular() {
		t.Fatalf("FIFO not replaced: %v", fi.Mode())
	}
}
