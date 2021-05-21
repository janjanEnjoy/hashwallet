package hash

import (
	"crypto/sha256"

	"golang.org/x/crypto/ripemd160"
)

// Sha256d calculates hash(hash(b)) and returns the resulting bytes.
func Sha256d(b []byte) []byte {
	first := sha256.Sum256(b)
	second := sha256.Sum256(first[:])
	return second[:]
}

// Hash160 calculates the hash ripemd160(sha256(b)).
func Hash160(data []byte) []byte {
	h := sha256.Sum256(data)
	r := ripemd160.New()
	r.Write(h[:])
	return r.Sum(nil)
}
