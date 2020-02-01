package winternitz

import (
	"io"
	"testing"

	"golang.org/x/crypto/chacha20"
)

type prng struct {
	cipher *chacha20.Cipher
}

func (p *prng) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = 0
	}
	p.cipher.XORKeyStream(b, b)
	return len(b), nil
}

func newPRNG(seed []byte) *prng {
	c, err := chacha20.NewUnauthenticatedCipher(seed[:], make([]byte, 12))
	if err != nil {
		panic(err)
	}
	return &prng{cipher: c}
}

var (
	message   = []byte("message")
	seed      = make([]byte, 32)
	rng       = newPRNG(seed)
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
