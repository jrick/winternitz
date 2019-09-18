package winternitz

import (
	"io"
	"testing"

	"decred.org/cspp/chacha20prng"
)

var (
	message   = []byte("message")
	seed      = make([]byte, 32)
	rng       = chacha20prng.New(seed, 0)
	pk, sk, _ = GenerateKey(rng)
	sig       = Sign(sk, message)
)

func TestVerify(t *testing.T) {
	if !Verify(pk, message, sig) {
		t.Fatal("correct signature fails verify")
	}
}

type nopReader struct{}

func (nopReader) Read(b []byte) (int, error) { return len(b), nil }

var nopr io.Reader = nopReader{}

func BenchmarkGenerateKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateKey(nopr)
	}
}

func BenchmarkSignVerify(b *testing.B) {
	for i := 0; i < b.N; i++ {
		sig := Sign(sk, message)
		if !Verify(pk, message, sig) {
			b.Fatal("verify")
		}
	}
}
