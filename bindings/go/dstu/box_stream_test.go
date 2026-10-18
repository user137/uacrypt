package dstu

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Streaming crypto_box/crypto_box512 (T-265 format v3, T-269): NewBox(512)EncryptWriter/
// NewBox(512)DecryptReader over the C ABI's _seal_stream/_open_stream. Happy path: the shared v3
// vectors (one-shot Open and the streaming reader), a round trip across record boundaries,
// one-shot/streaming byte equivalence. Security: tampering, a wrong key, trailing data. Misuse: a
// cut prefix, the 0.4-0.6 format (an unsupported version even when shorter than a v3 blob - the
// T-265 "too short" mislabel). Error path: Close without Complete leaves no Final record (D-118).

type boxVectors struct {
	Box256SecretKeyHex string `json:"box256_secret_key_hex"`
	Box512SecretKeyHex string `json:"box512_secret_key_hex"`
	Cases              []struct {
		Curve        int    `json:"curve"`
		Name         string `json:"name"`
		Expect       string `json:"expect"`
		PlaintextLen int    `json:"plaintext_len"`
		SealedHex    string `json:"sealed_hex"`
	} `json:"cases"`
}

func loadBoxVectors(t *testing.T, name string) boxVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "crates", "dstu-core", "tests", "vectors", "box", name))
	if err != nil {
		t.Fatal(err)
	}
	var v boxVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func pattern(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte((i*31 + 7) % 256)
	}
	return out
}

// boxCurve puts one curve's operations behind a common shape, so each test runs on both.
type boxCurve struct {
	open     func([]byte) ([]byte, error)
	reader   func(io.Reader) (*SecretStreamDecryptReader, error)
	writer   func(io.Writer) (*SecretStreamEncryptWriter, error)
	closeAll func()
}

func newBoxCurve(t *testing.T, bits int, secret []byte) boxCurve {
	t.Helper()
	if bits == 256 {
		var sk *BoxSecretKey
		var err error
		if secret == nil {
			sk, err = GenerateBoxSecretKey()
		} else {
			sk, err = BoxSecretKeyFromBytes(secret)
		}
		if err != nil {
			t.Fatal(err)
		}
		pk := sk.PublicKey()
		return boxCurve{
			open:     sk.Open,
			reader:   func(r io.Reader) (*SecretStreamDecryptReader, error) { return NewBoxDecryptReader(r, sk, true) },
			writer:   func(w io.Writer) (*SecretStreamEncryptWriter, error) { return NewBoxEncryptWriter(w, pk, true) },
			closeAll: func() { sk.Close(); pk.Close() },
		}
	}
	var sk *Box512SecretKey
	var err error
	if secret == nil {
		sk, err = GenerateBox512SecretKey()
	} else {
		sk, err = Box512SecretKeyFromBytes(secret)
	}
	if err != nil {
		t.Fatal(err)
	}
	pk := sk.PublicKey()
	return boxCurve{
		open:     sk.Open,
		reader:   func(r io.Reader) (*SecretStreamDecryptReader, error) { return NewBox512DecryptReader(r, sk, true) },
		writer:   func(w io.Writer) (*SecretStreamEncryptWriter, error) { return NewBox512EncryptWriter(w, pk, true) },
		closeAll: func() { sk.Close(); pk.Close() },
	}
}

func (c boxCurve) streamOpen(sealed []byte) ([]byte, error) {
	r, err := c.reader(bytes.NewReader(sealed))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

func (c boxCurve) streamSeal(t *testing.T, message []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := c.writer(&buf)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	first := min(7, len(message))
	if _, err := w.Write(message[:first]); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(message[first:]); err != nil {
		t.Fatal(err)
	}
	if err := w.Complete(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func secretField(v boxVectors, bits int) string {
	if bits == 256 {
		return v.Box256SecretKeyHex
	}
	return v.Box512SecretKeyHex
}

func TestBoxStreamSharedV3Vectors(t *testing.T) {
	v := loadBoxVectors(t, "v3.json")
	for _, bits := range []int{256, 512} {
		c := newBoxCurve(t, bits, mustHex(t, secretField(v, bits)))
		seen := 0
		for _, tc := range v.Cases {
			if tc.Curve != bits {
				continue
			}
			sealed := mustHex(t, tc.SealedHex)
			oneShot, errOne := c.open(sealed)
			streamed, errStream := c.streamOpen(sealed)
			if tc.Expect == "ok" {
				want := pattern(tc.PlaintextLen)
				if errOne != nil || errStream != nil || !bytes.Equal(oneShot, want) || !bytes.Equal(streamed, want) {
					t.Fatalf("box%d %s: one-shot %v, streaming %v", bits, tc.Name, errOne, errStream)
				}
			} else if errOne == nil || errStream == nil {
				t.Fatalf("box%d %s accepted (one-shot %v, streaming %v)", bits, tc.Name, errOne, errStream)
			}
			seen++
		}
		if seen == 0 {
			t.Fatalf("box%d: no cases", bits)
		}
		c.closeAll()
	}
}

func TestBoxStreamRefusesTheZeroSixFormatAsAnUnsupportedVersion(t *testing.T) {
	v := loadBoxVectors(t, "legacy_v2.json")
	for _, bits := range []int{256, 512} {
		c := newBoxCurve(t, bits, mustHex(t, secretField(v, bits)))
		for _, tc := range v.Cases {
			if tc.Curve != bits {
				continue
			}
			sealed := mustHex(t, tc.SealedHex)
			if _, err := c.open(sealed); err == nil || !strings.Contains(err.Error(), "version") {
				t.Fatalf("box%d one-shot: %v, want an unsupported-version error", bits, err)
			}
			if _, err := c.streamOpen(sealed); err == nil || !strings.Contains(err.Error(), "version") {
				t.Fatalf("box%d streaming: %v, want an unsupported-version error", bits, err)
			}
		}
		c.closeAll()
	}
}

func TestBoxStreamRoundTripReadsBackStreamingAndOneShot(t *testing.T) {
	for _, bits := range []int{256, 512} {
		c := newBoxCurve(t, bits, nil)
		for _, size := range []int{0, 1, 8 * 1024, 8*1024 + 1, 3*8*1024 + 5} {
			message := pattern(size)
			sealed := c.streamSeal(t, message)
			streamed, err := c.streamOpen(sealed)
			if err != nil || !bytes.Equal(streamed, message) {
				t.Fatalf("box%d size %d streaming: %v", bits, size, err)
			}
			oneShot, err := c.open(sealed)
			if err != nil || !bytes.Equal(oneShot, message) {
				t.Fatalf("box%d size %d one-shot: %v", bits, size, err)
			}
		}
		c.closeAll()
	}
}

func TestBoxStreamTamperingAWrongKeyAndTrailingDataFailClosed(t *testing.T) {
	var cryptoErr *CryptoError
	for _, bits := range []int{256, 512} {
		c := newBoxCurve(t, bits, nil)
		other := newBoxCurve(t, bits, nil)
		sealed := c.streamSeal(t, pattern(100))
		if _, err := other.streamOpen(sealed); !errors.As(err, &cryptoErr) {
			t.Fatalf("box%d wrong key: %v", bits, err)
		}
		for _, index := range []int{1, len(sealed) / 2, len(sealed) - 1} {
			bad := bytes.Clone(sealed)
			bad[index] ^= 1
			if _, err := c.streamOpen(bad); !errors.As(err, &cryptoErr) {
				t.Fatalf("box%d flipped byte %d: %v", bits, index, err)
			}
		}
		if _, err := c.streamOpen(append(bytes.Clone(sealed), 0)); !errors.As(err, &cryptoErr) {
			t.Fatalf("box%d trailing data: %v", bits, err)
		}
		c.closeAll()
		other.closeAll()
	}
}

func TestBoxStreamRefusesACutPrefixAsTooShort(t *testing.T) {
	for _, bits := range []int{256, 512} {
		c := newBoxCurve(t, bits, nil)
		sealed := c.streamSeal(t, pattern(10))
		for _, cut := range []int{0, 1, 50} {
			if _, err := c.streamOpen(sealed[:cut]); err == nil || !strings.Contains(err.Error(), "too short") {
				t.Fatalf("box%d cut %d: %v", bits, cut, err)
			}
		}
		c.closeAll()
	}
}

func TestBoxStreamCloseWithoutCompleteLeavesNoFinalRecord(t *testing.T) {
	for _, bits := range []int{256, 512} {
		c := newBoxCurve(t, bits, nil)
		var buf bytes.Buffer
		w, err := c.writer(&buf)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(pattern(3 * 8 * 1024)); err != nil {
			t.Fatal(err)
		}
		w.Close()
		if _, err := c.streamOpen(buf.Bytes()); err == nil {
			t.Fatalf("box%d: a stream without Final was accepted", bits)
		}
		c.closeAll()
	}
}
