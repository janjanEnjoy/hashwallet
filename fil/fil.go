package fil

import (
	"e.coding.net/webees/library/hdwallet/bip32"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/filecoin-project/go-address"
)

const (
	purposeID = bip32.HardenedKeyStart + 44
	coinID    = bip32.HardenedKeyStart + 461

	tCoinID = bip32.HardenedKeyStart + 1
)

var (
	TEST           = false
	HDPrivateKeyID = [4]byte{0x04, 0x88, 0xad, 0xe4}
	HDPublicKeyID  = [4]byte{0x04, 0x88, 0xb2, 0x1e}
)

func Xpub(pvk string, accountID uint32) (string, error) {
	accountID = bip32.HardenedKeyStart + accountID
	key, e := bip32.Xkey(pvk, purposeID, coinType(), accountID, 0)
	if e != nil {
		return "", e
	}
	pbk, e := key.Neuter(HDPublicKeyID)
	if e != nil {
		return "", e
	}
	return pbk.String(), nil
}


func Addr(xpub string, index uint32) (string, error) {
	c, e := bip32.Xkey(xpub, index)
	if e != nil {
		return "", e
	}
	ec, e := c.ECPubKey()
	if e != nil {
		return "", e
	}
	ecdsa := ec.ToECDSA()
	pbk := crypto.FromECDSAPub(ecdsa)
	if TEST {
		address.CurrentNetwork = address.Testnet
	} else {
		address.CurrentNetwork = address.Mainnet
	}
	a, e := address.NewSecp256k1Address(pbk)
	if e != nil {
		return "", e
	}
	return a.String(), nil
}
