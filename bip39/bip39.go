package bip39

import (
	"github.com/tyler-smith/go-bip39"
)

// 创建助记词
func NewMnemonic() (string, error) {
	entropy, e := bip39.NewEntropy(256)
	if e != nil {
		return "", e
	}
	mnemonic, e := bip39.NewMnemonic(entropy)
	if e != nil {
		return "", e
	}
	return mnemonic, nil
}

// 创建给定词的种子
func NewSeed(mnemonic string, password string) ([]byte, error) {
	seed, e := bip39.NewSeedWithErrorChecking(mnemonic, password)
	if e != nil {
		return nil, e
	}
	return seed, nil
}
