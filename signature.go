// Package winternitz implements the Winternitz one-time signature scheme using
// the Blake2b-256 hash function and a Winternitz compression parameter w of 256.
//
// Secret keys are one time use.  A secret key must not sign more than one
// message.
//
// Hash-based signature schemes are of particular interest and importance due to
// the belief that they are resistant against quantum computing attacks.  Unlike
// RSA and ECDSA, hash-based signatures do not rely on the discrete logarithm
// problem (which a quantum computer can solve in polynomial time) as being
// computationally hard.
//
// This package has not received an independent security audit.
package winternitz

import (
	"bytes"
	"encoding/binary"
	"io"

	"decred.org/cspp/chacha20prng"
	"golang.org/x/crypto/blake2b"
)

// SecretKey is a seed for creating the initial hash list to create a Lamport
// signature with Winternitz compression.  Using a ChaCha20 CSPRNG, it is
// expanded to create 34 secret seeds (32 values for each byte of the message
// hash, plus 2 extra values for signing 2 bytes of checksum) which are each
// Blake2b-256 hashed 255 times to result in 256 hash lists.  The final hash
// list is the full 1088 byte public key.
type SecretKey [32]byte

// PublicKey is a fingerprint of the final 1088-byte hash list.
//
// Verifying a valid signed message results in the recovery of the 1088-byte
// public key from the signature.  The public key hash list is then hashed with
// Blake2b-256 and compared to this fingerprint to determine signature validity.
type PublicKey [32]byte

// Signature is a proof that the possessor of the associated secret key for some
// public key has digitally signed a message, proving the authenticity of the
// message contents.
//
// Signature is constructed as the concatenation of 34 32-byte secret key values
// picked for each byte of the message hash and checksum, using the hash list
// for values of that byte.
//
// Because Signature is comprised the values from the expanded secret key hash
// lists, and message verification reveals the positions of these secrets in the
// hash lists, signing multiple messages with the same secret key is prohibited.
// Doing so destroys the security of this signature scheme by revealing
// preimages to forge signatures of other messages.
type Signature [1088]byte // 34 * 32

// GenerateKey derives a public and secret key, reading cryptographically-secure
// randomness from rand.
func GenerateKey(rand io.Reader) (pk *PublicKey, sk *SecretKey, err error) {
	sk = new(SecretKey)
	_, err = rand.Read(sk[:])
	if err != nil {
		return
	}

	// A full secret key contains 256 hash lists (each list being 32 hashes long).
	// The first hash list is created from the 32 byte secret seed,
	// and all other lists are hashes of each hash in the previous list.
	// The final hash list is the public key.
	// To generate this public key, the first hash list is seeded using ChaCha20
	// and each 32-byte hash is hashed 255 times to end at the public key portion.
	// As a space optimization, hashes are performed in place instead of creating
	// each of the 256 hash lists individually.
	var y [34 * 32]byte
	chacha20prng.New(sk[:], 0).Read(y[:])   // never errors
	for off := 0; off < len(y); off += 32 { // Iterate through each hash of this hash list
		var h [32]byte
		copy(h[:], y[off:off+32])
		for i := 0; i < 256; i++ {
			h = blake2b.Sum256(h[:])
		}
		copy(y[off:off+32], h[:])
	}

	pk = new(PublicKey)
	fingerprint := blake2b.Sum256(y[:])
	copy(pk[:], fingerprint[:])

	return
}

// checksummedMessageHash returns H(m)|C where C is a 2-byte little-endian
// checksum recording the total sum of differences between each signature hash
// list index and the public key hash list index 255.
//
// A checksum is decreased for each byte value closer to the public key value.
// Because the checksum is also signed, it prevents the forging of signatures
// from an original signature whose message hash only contains bytes larger than
// the original message hash.  For this attack to succeed, the preimages of the
// signature values for the original checksum would be required, which an
// attacker would not have access to so long as the secret key is protected and
// does not sign multiple messages.
func checksummedMessageHash(m []byte) [34]byte {
	var messageHashChecksum [34]byte

	messageHash := blake2b.Sum256(m)
	copy(messageHashChecksum[:32], messageHash[:])

	var cksum uint16
	for _, b := range messageHash {
		cksum += 255 - uint16(b)
	}
	binary.LittleEndian.PutUint16(messageHashChecksum[32:], cksum)

	return messageHashChecksum
}

// Sign signs message with sk.
//
// Signing is a one-time operation: different messages must not be signed using
// the same secret key.  Failure to observe this requirement may result in the
// forging of signatures for other messages.
func Sign(sk *SecretKey, message []byte) *Signature {
	messageHash := checksummedMessageHash(message)

	var y [len(messageHash) * 32]byte
	chacha20prng.New(sk[:], 0).Read(y[:]) // never errors
	for i, b := range messageHash {
		bytesig := y[i*32 : i*32+32]
		var h [32]byte
		copy(h[:], bytesig)
		for j := byte(0); j < b; j++ {
			h = blake2b.Sum256(h[:])
		}
		copy(bytesig, h[:])
	}

	return (*Signature)(&y)
}

// Verify checks whether sig is a valid signature created by the secret key of
// pk for message.
func Verify(pk *PublicKey, message []byte, sig *Signature) bool {
	messageHash := checksummedMessageHash(message)

	var y [len(messageHash) * 32]byte = *sig
	for i, b := range messageHash {
		bytepub := y[i*32 : i*32+32]
		var h [32]byte
		copy(h[:], bytepub)
		for j := 255 - int(b); j >= 0; j-- {
			h = blake2b.Sum256(h[:])
		}
		copy(bytepub, h[:])
	}

	// Signature is verified if the hash of the pubkey (which is the hashing
	// of each signature hash to the pubkey portion) matches the public key
	// parameter (actually a fingerprint).
	fingerprint := blake2b.Sum256(y[:])
	return bytes.Equal(pk[:], fingerprint[:])
}
