package dstu

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// repoRoot finds the repo root relative to this package directory (bindings/go/dstu, three
// levels down from the repo root) - go test always runs with its working directory set to the
// package's own source directory, so this is stable regardless of how `go test` was invoked,
// same reasoning as bindings/dotnet/DstuCore.Tests's own RepoRoot.cs.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(wd, "..", "..", "..")
}

type vectorFile struct {
	Cases []map[string]json.RawMessage `json:"cases"`
}

// loadFirstVectorCase returns the first case's string-valued fields (message_hex/hash_hex/etc.) -
// vector JSON also carries non-string fields (message_bits as a number), so this only decodes the
// ones that unmarshal cleanly as a Go string, silently skipping the rest.
func loadFirstVectorCase(t *testing.T, relPath string) map[string]string {
	t.Helper()
	path := filepath.Join(repoRoot(t), filepath.FromSlash(relPath))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var vf vectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatal(err)
	}
	if len(vf.Cases) == 0 {
		t.Fatalf("%s: no cases", path)
	}
	out := make(map[string]string)
	for k, raw := range vf.Cases[0] {
		var s string
		if json.Unmarshal(raw, &s) == nil {
			out[k] = s
		}
	}
	return out
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// findUacrypt locates a real, already-built uacrypt binary for the secretstream interop test.
// Returns "" if not built - the caller skips rather than fails, matching bindings/python's own
// skipif and bindings/dotnet's own FindUacrypt.
func findUacrypt(t *testing.T) string {
	t.Helper()
	root := repoRoot(t)
	candidates := []string{
		filepath.Join(root, "target", "debug", "uacrypt.exe"),
		filepath.Join(root, "target", "release", "uacrypt.exe"),
		filepath.Join(root, "target", "debug", "uacrypt"),
		filepath.Join(root, "target", "release", "uacrypt"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}
