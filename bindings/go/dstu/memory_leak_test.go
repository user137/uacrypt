package dstu

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// T-213: FFI memory-leak smoke test.
//
// This binding uses cgo to call into dstu-core-capi's C ABI, so native memory freed by
// dstu_*_free is allocated outside Go's own runtime heap - confirmed by reasoning, not
// guessed: cgo allocations made on the C side are invisible to runtime.ReadMemStats, which
// only accounts for memory the Go allocator itself manages. That's the same underlying
// category as the Java/.NET bindings' own T-213 tests in this batch (a native handle behind
// a Close()/finalizer, no Go-heap signal to observe it by) - see those two tests' doc
// comments for the two Windows-local measurement attempts (GC.GetTotalMemory-style JVM/CLR
// heap counters, then in-process working-set sampling) that were tried and rejected there
// before landing on the same mechanism this test uses: /proc/self/status's VmRSS, Linux-only,
// skipped elsewhere. Not re-attempting either rejected mechanism here is a deliberate
// consequence of this project's three-attempts rule (already spent on the same underlying
// question twice this batch), not an oversight.
//
// Not verified on this project's own Windows dev machine, matching the existing documented
// precedent for uacrypt_with_peak_rss's own Linux/macOS paths in the CLI test suite (reviewed,
// not run, before their first real CI confirmation) and this same T-213 batch's Java/.NET tests.
func currentVmRssBytes(tb testing.TB) int64 {
	tb.Helper()
	f, err := os.Open("/proc/self/status")
	if err != nil {
		tb.Fatalf("open /proc/self/status: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			kb, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				tb.Fatalf("parse VmRSS value %q: %v", fields[1], err)
			}
			return kb * 1024
		}
	}
	tb.Fatal("VmRSS line not found in /proc/self/status")
	return 0
}

func runSecretstreamAndBoxLoop(tb testing.TB, key *SecretstreamKey, boxSecret *BoxSecretKey, boxPublic *BoxPublicKey, n int) {
	tb.Helper()
	for i := 0; i < n; i++ {
		var buf bytes.Buffer
		w, err := NewSecretStreamEncryptWriter(&buf, key, true)
		if err != nil {
			tb.Fatal(err)
		}
		if _, err := w.Write([]byte("leak-check chunk")); err != nil {
			tb.Fatal(err)
		}
		if err := w.Complete(); err != nil {
			tb.Fatal(err)
		}
		if err := w.Close(); err != nil {
			tb.Fatal(err)
		}

		r, err := NewSecretStreamDecryptReader(&buf, key, true)
		if err != nil {
			tb.Fatal(err)
		}
		got, err := io.ReadAll(r)
		if err != nil {
			tb.Fatal(err)
		}
		if string(got) != "leak-check chunk" {
			tb.Fatalf("secretstream round-trip mismatch: got %q", got)
		}
		if err := r.Close(); err != nil {
			tb.Fatal(err)
		}

		sealed, err := boxPublic.Seal([]byte("leak-check message"))
		if err != nil {
			tb.Fatal(err)
		}
		opened, err := boxSecret.Open(sealed)
		if err != nil {
			tb.Fatal(err)
		}
		if string(opened) != "leak-check message" {
			tb.Fatalf("box round-trip mismatch: got %q", opened)
		}
	}
}

func TestSecretstreamAndBoxLoopDoesNotLeak(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("VmRSS-based leak check only runs on Linux - see file doc comment for why the Windows-local alternatives were rejected")
	}

	const warmup = 2000
	const n = 20000
	// Comfortable margin above normal churn but far below what N leaked handles would show at
	// this scale - same order of magnitude as this batch's Java/.NET thresholds.
	const maxAcceptableGrowthBytes = 8 * 1024 * 1024

	key, err := GenerateSecretstreamKey()
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()
	boxSecret, err := GenerateBoxSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	defer boxSecret.Close()
	boxPublic := boxSecret.PublicKey()
	defer boxPublic.Close()

	runSecretstreamAndBoxLoop(t, key, boxSecret, boxPublic, warmup)
	runtime.GC()
	before := currentVmRssBytes(t)

	runSecretstreamAndBoxLoop(t, key, boxSecret, boxPublic, n)

	runtime.GC()
	after := currentVmRssBytes(t)
	growth := after - before
	if growth >= maxAcceptableGrowthBytes {
		t.Fatalf("VmRSS grew by %d bytes over %d iterations (threshold %d) - possible native handle leak", growth, n, maxAcceptableGrowthBytes)
	}
}
