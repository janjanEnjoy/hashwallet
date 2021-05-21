package eth

import (
	"encoding/json"
	"math/big"
	"strconv"

	"e.coding.net/webees/library/hdwallet/bip32"
	"github.com/btcsuite/btcutil/base58"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

const (
	purposeID       = bip32.HardenedKeyStart + 44
	coinID          = bip32.HardenedKeyStart + 60
	chainId   int64 = 1

	tChainId int64 = 3
	tCoinID        = bip32.HardenedKeyStart + 1

	// todo:
	USDT      = "0xdac17f958d2ee523a2206206994597c13d831ec7" // USDT token address
	TEST_USDT = "0x1b01cdb8ecbec888f09d8919242f818a1790f20c"
)

var (
	TEST           = false
	HDPrivateKeyID = [4]byte{0x04, 0x88, 0xad, 0xe4}
	HDPublicKeyID  = [4]byte{0x04, 0x88, 0xb2, 0x1e}
)

type RawTx struct {
	LegacyTx  types.LegacyTx
	FromIndex int
}

func Xpub(pvk string, accountID uint32) (string, error) {
	var cid uint32
	if TEST {
		cid = tCoinID
	} else {
		cid = coinID
	}
	key, e := bip32.Xkey(pvk, purposeID, cid, 2147483648, 0)
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
	return crypto.PubkeyToAddress(*ecdsa).Hex(), nil
}

// 未签名raw
func UnsignedRaw(fromIndex int, nonce uint64, toAddress string, amount string, gasLimit uint64, gasPrice uint64, tokenAddress ...string) (string, error) {
	data := []byte(nil)
	// 如果传入Erc20代币地址
	if len(tokenAddress) > 0 {
		tokenAddr := tokenAddress[0]
		data = erc20data(toAddress, amount)
		toAddress = tokenAddr
		amount = strconv.Itoa(0)
	}
	bGasPrice := big.NewInt(int64(gasPrice))
	toAddr := common.HexToAddress(toAddress) // 发送地址
	bAmount := new(big.Int)                  // 交易数量
	bAmount.SetString(amount, 0)
	rawTx := RawTx{ // 构造原始交易对象
		LegacyTx: types.LegacyTx{
			Nonce:    nonce,
			GasPrice: bGasPrice,
			Gas:      gasLimit,
			To:       &toAddr,
			Value:    bAmount,
			Data:     data,
			V:        nil,
			R:        nil,
			S:        nil,
		},
		FromIndex: fromIndex,
	}
	j, e := json.Marshal(rawTx)
	if e != nil {
		return "", e
	}
	return base58.Encode(j), nil
}

// 签名raw
func SignedRaw(raw string, xpvk string) (string, error) {
	b := base58.Decode(raw) // 解析还原交易数据
	rawTx := RawTx{}
	e := json.Unmarshal(b, &rawTx)
	if e != nil {
		return "", e
	}
	tx := types.NewTx(&rawTx.LegacyTx)
	pvk, e := addrPvk(xpvk, rawTx.FromIndex) // 获取发送指定索引地址私钥
	if e != nil {
		return "", e
	}
	var cid int64
	if TEST {
		cid = tChainId
	} else {
		cid = chainId
	}
	// 签名
	signedTx, e := types.SignTx(tx, types.NewEIP155Signer(big.NewInt(cid)), pvk)
	if e != nil {
		return "", e
	}
	// 序列化
	b, e = rlp.EncodeToBytes(signedTx)
	if e != nil {
		return "", e
	}
	s := hexutil.Encode(b)
	return s, nil
}
