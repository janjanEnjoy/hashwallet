package bip32

import (
	"encoding/binary"
	"errors"

	"e.coding.net/webees/library/hdwallet/crypto/hash"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil/base58"
)

// PubKeyBytes returns bytes for the serialized compressed public key associated
// with this extended key in an efficient manner including memoization as
// necessary.
//
// When the extended key is already a public key, the key is simply returned as
// is since it's already in the correct form.  However, when the extended key is
// a private key, the public key will be calculated and memoized so future
// accesses can simply return the cached result.
func (k *ExtendedKey) PubKeyBytes() []byte {
	// Just return the key if it's already an extended public key.
	if !k.isPrivate {
		return k.key
	}
	// This is a private extended key, so calculate and memoize the public
	// key if needed.
	if len(k.pubKey) == 0 {
		pkx, pky := btcec.S256().ScalarBaseMult(k.key)
		pubKey := btcec.PublicKey{Curve: btcec.S256(), X: pkx, Y: pky}
		k.pubKey = pubKey.SerializeCompressed()
	}
	return k.pubKey
}

// String returns the extended key as a human-readable base58-encoded string.
func (k *ExtendedKey) String() string {
	if len(k.key) == 0 {
		return "zeroed extended key"
	}

	var childNumBytes [4]byte
	binary.BigEndian.PutUint32(childNumBytes[:], k.childNum)

	// The serialized format is:
	//   version (4) || depth (1) || parent fingerprint (4)) ||
	//   child num (4) || chain code (32) || key data (33) || checksum (4)
	serializedBytes := make([]byte, 0, serializedKeyLen+4)
	serializedBytes = append(serializedBytes, k.version...)
	serializedBytes = append(serializedBytes, k.depth)
	serializedBytes = append(serializedBytes, k.parentFP...)
	serializedBytes = append(serializedBytes, childNumBytes[:]...)
	serializedBytes = append(serializedBytes, k.chainCode...)
	if k.isPrivate {
		serializedBytes = append(serializedBytes, 0x00)
		serializedBytes = paddedAppend(32, serializedBytes, k.key)
	} else {
		serializedBytes = append(serializedBytes, k.PubKeyBytes()...)
	}

	checkSum := hash.Sha256d(serializedBytes)[:4]
	serializedBytes = append(serializedBytes, checkSum...)
	return base58.Encode(serializedBytes)
}

// Neuter returns a new extended public key from this extended private key.  The
// same extended key will be returned unaltered if it is already an extended
// public key.
//
// As the name implies, an extended public key does not have access to the
// private key, so it is not capable of signing transactions or deriving
// child extended private keys.  However, it is capable of deriving further
// child extended public keys.
func (k *ExtendedKey) Neuter(HDPublicKeyID [4]byte) (*ExtendedKey, error) {
	// Already an extended public key.
	if !k.isPrivate {
		return k, nil
	}

	// Convert it to an extended public key.  The key for the new extended
	// key will simply be the pubkey of the current extended private key.
	//
	// This is the function N((k,c)) -> (K, c) from [BIP32].
	return newExtendedKey(HDPublicKeyID[:], k.PubKeyBytes(), k.chainCode, k.parentFP, k.depth, k.childNum, false), nil
}

// ECPubKey converts the extended key to a btcec public key and returns it.
func (k *ExtendedKey) ECPubKey() (*btcec.PublicKey, error) {
	return btcec.ParsePubKey(k.PubKeyBytes(), btcec.S256())
}

// ECPrivKey converts the extended key to a btcec private key and returns it.
// As you might imagine this is only possible if the extended key is a private
// extended key (as determined by the IsPrivate function).  The ErrNotPrivExtKey
// error will be returned if this function is called on a public extended key.
func (k *ExtendedKey) ECPrivKey() (*btcec.PrivateKey, error) {
	if !k.isPrivate {
		return nil, errors.New("unable to create private keys from a public extended key")
	}

	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), k.key)
	return privKey, nil
}

