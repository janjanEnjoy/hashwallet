package eth

import (
	"bytes"
	"crypto/ecdsa"
	"math/big"

	"e.coding.net/webees/library/hdwallet/bip32"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"golang.org/x/crypto/sha3"
)

// 获取地址索引对应的私钥
func addrPvk(xpvk string, fromIndex int) (*ecdsa.PrivateKey, error) {
	var cid uint32
	if TEST {
		cid = tCoinID
	} else {
		cid = coinID
	}
	xkey, e := bip32.Xkey(xpvk, purposeID, cid, 2147483648, 0, uint32(fromIndex))
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

// 获取r、s、v (验证可用)
func rsv(signedTx *types.Transaction) (r []byte, s []byte, v []byte) {
	bi_v, bi_s, bi_r := signedTx.RawSignatureValues()
	r = bi_r.Bytes()
	s = bi_s.Bytes()
	v = bi_v.Bytes()
	return r, s, v
}

// 代币Data
func erc20data(to string, amount string) []byte {
	transferFnSignature := []byte("transfer(address,uint256)")
	// 传输协议方法hash
	hash := sha3.NewLegacyKeccak256()
	hash.Write(transferFnSignature)
	methodID := hash.Sum(nil)[:4] //a9059cbb
	// 发送地址
	toAddr := common.HexToAddress(to)
	paddedAddress := common.LeftPadBytes(toAddr.Bytes(), 32)
	// 代币数量
	bAmount := new(big.Int)
	bAmount.SetString(amount, 0)
	paddedAmount := common.LeftPadBytes(bAmount.Bytes(), 32)

	var data bytes.Buffer
	data.Write(methodID)
	data.Write(paddedAddress)
	data.Write(paddedAmount)
	return data.Bytes()
}
