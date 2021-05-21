package trx

import (
	"crypto/sha256"
	"e.coding.net/webees/library/hdwallet/bip32"
	ptc "e.coding.net/webees/library/hdwallet/trx/protocol"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/fbsobreira/gotron-sdk/pkg/common"
	"github.com/golang/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"time"
)

const (
	purposeID = bip32.HardenedKeyStart + 44
	coinID    = bip32.HardenedKeyStart + 195
	// addrID is the byte prefix of the address used in TRON addresses.
	// It's supposed to be '0xa0' for testnet, and '0x41' for mainnet.
	// But the Shasta mainteiners don't use the testnet params. So the default value is 41.
	addrID        = 0x41
	chainId int64 = 1

	tChainId int64 = 3
	tCoinID        = bip32.HardenedKeyStart + 1

	EXPIRE = 6000 // 交易过期时间：ms
)

type RawTx struct {
	LegacyTx  types.LegacyTx
	FromIndex int
}

var (
	TEST           = false
	HDPrivateKeyID = [4]byte{0x04, 0x88, 0xad, 0xe4}
	HDPublicKeyID  = [4]byte{0x04, 0x88, 0xb2, 0x1e}
)

func Xpub(pvk string, accountID uint32) (string, error) {
	key, e := bip32.Xkey(pvk, purposeID, coinType(), 2147483648, 0)
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
	return base58.CheckEncode(crypto.PubkeyToAddress(*ecdsa).Bytes(), addrID), nil
}

// 待签名交易
func UnsignedRaw(from string, to string, amount int64, blockBytes string, blockHash string, timestamp ...int64) (string, error) {
	// 发送与目标地址base58后，截断后4位
	bfrom := base58.Decode(from)
	if len(bfrom) < 4 {
		return "", errors.New("发送地址错误")
	}
	bto := base58.Decode(to)
	if len(bto) < 4 {
		return "", errors.New("目标地址错误")
	}
	bfrom = bfrom[0 : len(bfrom)-4]
	fmt.Printf("bfrom=%02x\n", bfrom)

	bto = bto[0 : len(bto)-4]
	fmt.Printf("bto=%02x\n", bto)

	t := time.Now().UnixNano() / 1000000
	fmt.Println("now=", t)
	if len(timestamp) > 0 {
		t = timestamp[0]
	}
	expire := t + EXPIRE // 延迟一分钟过期
	if len(timestamp) >= 2 {
		expire = timestamp[1]
	}
	fmt.Println("t=：", t)
	fmt.Println("exprt=", expire)
	// 构建parameter：发送地址、目标地址和金额
	any := ptc.TransferContract{OwnerAddress: bfrom, ToAddress: bto, Amount: amount}
	param, _ := anypb.New(&any)
	// 构建contract
	crt := make([]*ptc.Contract, 0)
	crt = append(crt, &ptc.Contract{
		Type:         1,
		Parameter:    param,
		Provider:     nil,
		ContractName: nil,
		PermissionId: 0,
	})
	bb, _ := hex.DecodeString(blockBytes)
	bh, _ := hex.DecodeString(blockHash)
	// 构建raw
	a := &ptc.Raw{
		RefBlockBytes: bb,
		RefBlockNum:   0,
		RefBlockHash:  bh,
		Expiration:    expire,
		Auths:         nil,
		Data:          nil,
		Contract:      crt,
		Scripts:       nil,
		Timestamp:     t,
		FeeLimit:      0,
	}

	res, e := proto.Marshal(a) // 序列化
	if e != nil {
		return "", e
	}

	std := "0a029c50220822b0f76cf489bad840c0d4c6b18a2f5a68080112640a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412330a15414a075b549dd609d50dc772f6187903b4825f8444121541cd70082c54d9a9eb7d03770e4b6476748fa3f6d0188084af5f70a48bc3b18a2f"
	asi := hex.EncodeToString(res)
	fmt.Println("raw 标准=", std)
	fmt.Println("raw 测试=", asi)
	fmt.Println("结果：", std == asi)
	return hex.EncodeToString(res), nil
}

// 签名
func SignedRaw(raw []byte, pvk string) (string, error, string) {
	privateKeyECDSA, _ := addrPvk(pvk, 0)

	h256h := sha256.New()
	h256h.Write(raw[:])
	txHash := h256h.Sum(nil)
	fmt.Printf("tx hash=%02x\n", txHash)
	signature, err := crypto.Sign(txHash, privateKeyECDSA)
	if err != nil {
		return "", err,""
	}
	return hex.EncodeToString(signature), nil,hex.EncodeToString(txHash)
}

// 待签名交易TEST(返回增加from,to,block信息等，用于构建广播数据体)
func UnsignedRaw1(from string, to string, amount int64, blockBytes string, blockHash string, timestamp ...int64) (string, error, string, string, int64, int64) {
	// 发送与目标地址base58后，截断后4位
	bfrom := base58.Decode(from)
	if len(bfrom) < 4 {
		return "", errors.New("发送地址错误"), "", "", 0, 0
	}
	bto := base58.Decode(to)
	if len(bto) < 4 {
		return "", errors.New("目标地址错误"), "", "", 0, 0
	}
	bfrom = bfrom[0 : len(bfrom)-4]
	fmt.Printf("bfrom=%02x\n", bfrom)

	bto = bto[0 : len(bto)-4]
	fmt.Printf("bto=%02x\n", bto)

	t := time.Now().Unix() * 1000
	fmt.Println("now=", t)
	if len(timestamp) > 0 {
		t = timestamp[0]
	}
	expire := t + EXPIRE // 延迟一分钟过期
	if len(timestamp) >= 2 {
		expire = timestamp[1]
	}
	fmt.Println("t=：", t)
	fmt.Println("exprt=", expire)
	// 构建parameter：发送地址、目标地址和金额
	any := ptc.TransferContract{OwnerAddress: bfrom, ToAddress: bto, Amount: amount}
	param, _ := anypb.New(&any)
	// 构建contract
	crt := make([]*ptc.Contract, 0)
	crt = append(crt, &ptc.Contract{
		Type:         1,
		Parameter:    param,
		Provider:     nil,
		ContractName: nil,
		PermissionId: 0,
	})
	bb, _ := hex.DecodeString(blockBytes)
	bh, _ := hex.DecodeString(blockHash)
	// 构建raw
	a := &ptc.Raw{
		RefBlockBytes: bb,
		RefBlockNum:   0,
		RefBlockHash:  bh,
		Expiration:    expire,
		Auths:         nil,
		Data:          nil,
		Contract:      crt,
		Scripts:       nil,
		Timestamp:     t,
		FeeLimit:      0,
	}
	res, e := proto.Marshal(a) // 序列化
	if e != nil {
		return "", e, "", "", 0, 0
	}
	return hex.EncodeToString(res), nil, common.ToHex(bfrom), common.ToHex(bto), t, expire
}

// 测试：增加返回txid hash，用于构造广播数据体
func SignedRaw1(raw []byte, pvk string) (string, error, string) {
	privateKeyECDSA, _ := addrPvk(pvk, 0)

	txHash := sha256.Sum256(raw)
	fmt.Println("txhash len = ", len(txHash))
	fmt.Printf("tx hash=%02x\n", txHash)
	signature, err := crypto.Sign(txHash[:], privateKeyECDSA)

	if err != nil {
		return "", err, ""
	}
	return hex.EncodeToString(signature), nil, common.ToHex(txHash[:])
}

// 待签名交易
func UnsignedRaw2(from string, to string, amount int64, blockBytes string, blockHash string, timestamp ...int64) (string, error) {
	// 发送与目标地址base58后，截断后4位
	bfrom := base58.Decode(from)
	if len(bfrom) < 4 {
		return "", errors.New("发送地址错误")
	}
	bto := base58.Decode(to)
	if len(bto) < 4 {
		return "", errors.New("目标地址错误")
	}
	bfrom = bfrom[0 : len(bfrom)-4]
	fmt.Printf("bfrom=%02x\n", bfrom)

	bto = bto[0 : len(bto)-4]
	fmt.Printf("bto=%02x\n", bto)

	t := time.Now().UnixNano() / 1000000
	fmt.Println("now=", t)
	if len(timestamp) > 0 {
		t = timestamp[0]
	}
	expire := t + EXPIRE // 延迟一分钟过期
	if len(timestamp) >= 2 {
		expire = timestamp[1]
	}
	fmt.Println("t=：", t)
	fmt.Println("exprt=", expire)
	// 构建parameter：发送地址、目标地址和金额
	any := ptc.TransferContract{OwnerAddress: bfrom, ToAddress: bto, Amount: amount}
	param, _ := anypb.New(&any)
	// 构建contract
	crt := make([]*ptc.Contract, 0)
	crt = append(crt, &ptc.Contract{
		Type:         1,
		Parameter:    param,
		Provider:     nil,
		ContractName: nil,
		PermissionId: 0,
	})
	bb, _ := hex.DecodeString(blockBytes)
	bh, _ := hex.DecodeString(blockHash)
	// 构建raw
	a := &ptc.Raw{
		RefBlockBytes: bb,
		RefBlockNum:   0,
		RefBlockHash:  bh,
		Expiration:    expire,
		Auths:         nil,
		Data:          nil,
		Contract:      crt,
		Scripts:       nil,
		Timestamp:     t,
		FeeLimit:      0,
	}

	res, e := proto.Marshal(a) // 序列化
	if e != nil {
		return "", e
	}

	std := "0a029c50220822b0f76cf489bad840c0d4c6b18a2f5a68080112640a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412330a15414a075b549dd609d50dc772f6187903b4825f8444121541cd70082c54d9a9eb7d03770e4b6476748fa3f6d0188084af5f70a48bc3b18a2f"
	asi := hex.EncodeToString(res)
	fmt.Println("raw 标准=", std)
	fmt.Println("raw 测试=", asi)
	fmt.Println("结果：", std == asi)
	return hex.EncodeToString(res), nil
}

func VerifySignature(publicKey, hash, signature []byte) bool {
	return crypto.VerifySignature(publicKey, hash, signature)
}
