package trx

import (
	"crypto/ecdsa"
	"e.coding.net/webees/library/hdwallet/bip32"
)

func coinType() uint32 {
	if TEST {
		return tCoinID
	} else {
		return coinID
	}
}

// 获取地址索引对应的私钥
func addrPvk(xpvk string, fromIndex int) (*ecdsa.PrivateKey, error) {
	xkey, e := bip32.Xkey(xpvk, purposeID, tCoinID, 2147483648, 0, uint32(fromIndex))
	if e != nil {
		return nil, e
	}
	ecKey, e := xkey.ECPrivKey()
	if e != nil {
		return nil, e
	}
	ecdsaKey := ecKey.ToECDSA()
	return ecdsaKey, nil
}
