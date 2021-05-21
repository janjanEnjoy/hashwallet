package trx

import (
	"crypto/sha256"
	"e.coding.net/webees/library/hdwallet/trx/protocol"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/gogf/gf/frame/g"
	"github.com/gogf/gf/os/glog"
	"github.com/gogf/gf/util/gconv"
	"github.com/golang/protobuf/proto"
	"github.com/tidwall/gjson"
	"strconv"
	"strings"
	"testing"
	"time"

	"e.coding.net/webees/library/hdwallet/bip32"
	"e.coding.net/webees/library/hdwallet/bip39"
	"github.com/gogf/gf/container/gmap"
)

func TestTrx(t *testing.T) {
	fmt.Println("\n######################################## TRX ########################################")
	mnemonic := "owner mosquito uphold xx xx xx xx xx vital chapter shoulder horn"  // 替换你的助记词
	seed, _ := bip39.NewSeed(mnemonic, "")
	pvk, _ := bip32.NewMaster(seed, HDPrivateKeyID)
	pbk, _ := Xpub(pvk.String(), 0)
	fmt.Println("\n助记词：  ", mnemonic)
	fmt.Println("扩展私钥: ", pvk.String())
	fmt.Println("账户公钥：", pbk)
	addr := gmap.New(true)
	start := time.Now()
	for i := 0; i < 9; i++ {
		s, _ := Addr(pbk, uint32(i))
		addr.Set(i, s)
		fmt.Println("地址", i, "=", s)
	}
	elapsed := time.Since(start)
	fmt.Println("\n耗时：", elapsed)
}

func TestTtrx(t *testing.T) {
	TEST = true
	fmt.Println("\n######################################## tTRX ########################################")
	mnemonic := "owner mosquito uphold xx xx xx xx xx vital chapter shoulder horn"  // 替换你的助记词
	seed, _ := bip39.NewSeed(mnemonic, "")
	pvk, _ := bip32.NewMaster(seed, HDPrivateKeyID)
	pbk, _ := Xpub(pvk.String(), 0)
	fmt.Println("\n助记词：  ", mnemonic)
	fmt.Println("扩展私钥: ", pvk.String())
	fmt.Println("账户公钥：", pbk)
	addr := gmap.New(true)
	start := time.Now()
	for i := 0; i < 9; i++ {
		s, _ := Addr(pbk, uint32(i))
		addr.Set(i, s)
		fmt.Println("地址", i, "=", s)
	}
	elapsed := time.Since(start)
	fmt.Println("\n耗时：", elapsed)
}

func TestUnsignedRaw(t *testing.T) {
	fmt.Println("\n######################################## UnsignedRaw ########################################")
	from := "TGidpQoA6dcFkuroitVi3kwdsdYdUdQ9zX"

	to := "TUhTjVtigt3oYFaSWLWQp2XC5FJBN26G1J"
	blockBytes := "9c50"
	blockHash := "22b0f76cf489bad8"
	amount := int64(200000000)
	current := int64(1617695917476)
	expire := int64(1617695976000)
	res, e := UnsignedRaw(from, to, amount, blockBytes, blockHash, current, expire)
	if e != nil {
		glog.Fatal(e)
	}
	fmt.Println("编码数据:", res)
	d := "0a029c50220822b0f76cf489bad840c0d4c6b18a2f5a68080112640a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412330a15414a075b549dd609d50dc772f6187903b4825f8444121541cd70082c54d9a9eb7d03770e4b6476748fa3f6d0188084af5f70a48bc3b18a2f"
	fmt.Println("正确数据:", d)
	fmt.Println("编码是否正确：", res == d)
}

func TestSignedRaw(t *testing.T) {
	fmt.Println("\n######################################## SignedRaw ########################################")
	mnemonic := "owner mosquito uphold xx xx xx xx xx vital chapter shoulder horn"  // 替换你的助记词
	seed, _ := bip39.NewSeed(mnemonic, "")
	pvk, _ := bip32.NewMaster(seed, HDPrivateKeyID)

	from := "TGidpQoA6dcFkuroitVi3kwdsdYdUdQ9zX"
	to := "TUhTjVtigt3oYFaSWLWQp2XC5FJBN26G1J"
	blockBytes := "9c50"
	blockHash := "22b0f76cf489bad8"
	amount := int64(200000000)
	current := int64(1617695917476)
	expire := int64(1617695976000)
	ss, _ := UnsignedRaw(from, to, amount, blockBytes, blockHash, current, expire)

	fmt.Println("temp=", ss)
	xpvk := pvk.String()


	xpvk2 := "xprv9s21ZrQH143K3YFpEoWtTFxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx18bG5MeBwm2KQCrwTMbM3V4qb1WvVcaygAp6WdVBL" // 替换助记词对应的私钥
	fmt.Println("pvk结果2：", xpvk2)
	fmt.Println("pvk结果1：", xpvk)
	fmt.Println("xpvk==xpvk2", xpvk == xpvk2)

	b_s, _ := hex.DecodeString(ss)

	res, _ ,_:= SignedRaw(b_s, xpvk)
	fmt.Println("签名结果1：", res)
	fmt.Println("正确结果0：", "6339ed0253074da5a8fffe391bf65978e9c33451d4cc3eff99abb1cd10d495f9ecd3c452b938570bb33af02f0cf984454eaa577d7fc7df2df36734ff6804fdd600")
}

// 测试广播新构造数据
func TestBroadTX(t *testing.T) {
	fmt.Println("\n######################################## SignedRaw ########################################")
	mnemonic := "owner mosquito uphold xx xx xx xx xx vital chapter shoulder horn"  // 替换你的助记词
	seed, _ := bip39.NewSeed(mnemonic, "")
	pvk, _ := bip32.NewMaster(seed, HDPrivateKeyID)

	from := "TGidpQoA6dcFkuroitVi3kwdsdYdUdQ9zX"
	to := "TUhTjVtigt3oYFaSWLWQp2XC5FJBN26G1J"
	blockBytes := "9c50"
	blockHash := "22b0f76cf489bad8"
	amount := int64(200000000)
	ss, _, ff, tt, time, ee := UnsignedRaw1(from, to, amount, blockBytes, blockHash)

	fmt.Println("temp=", ss)
	xpvk := pvk.String()

	fmt.Println("raw结果：", ss)

	b_s, _ := hex.DecodeString(ss)

	res, _, txid := SignedRaw1(b_s, xpvk)
	fmt.Println("签名结果：", res)

	url := "https://api.shasta.trongrid.io/wallet/broadcasttransaction"

	client := g.Client()

	param := g.Map{
		"txID": txid,
		"raw_data": g.Map{
			"contract": [...]g.Map{{
				"parameter": g.Map{
					"value": g.Map{
						"amount":        amount,
						"owner_address": ff,
						"to_address":    tt,
					},
					"type_url": "type.googleapis.com/protocol.TransferContract",
				},
				"type": "TransferContract",
			},
			},
			"ref_block_bytes": "9c50",
			"ref_block_hash":  "22b0f76cf489bad8",
			"expiration":      ee,
			"timestamp":       time,
		},
		"raw_data_hex": ss,
		"signatrure":   res,
	}

	j, _ := json.Marshal(param)
	js := string(j)
	fmt.Printf("参数=%#v\n", js)
	r, _ := client.Post(url, js)
	defer r.Close()
	s := r.ReadAllString()
	message := gjson.Get(s, "message")
	m, _ := hex.DecodeString(message.String())

	fmt.Printf("广播结果=%#v\n", string(m))
}

// 测试广播已上链完全相同交易
func TestBroadTX1(t *testing.T) {
	fmt.Println("\n######################################## SignedRaw ########################################")
	mnemonic := "owner mosquito uphold xx xx xx xx xx vital chapter shoulder horn"  // 替换你的助记词
	seed, _ := bip39.NewSeed(mnemonic, "")
	pvk, _ := bip32.NewMaster(seed, HDPrivateKeyID)

	from := "TGidpQoA6dcFkuroitVi3kwdsdYdUdQ9zX"
	to := "TUhTjVtigt3oYFaSWLWQp2XC5FJBN26G1J"
	blockBytes := "9c50"
	blockHash := "22b0f76cf489bad8"
	amount := int64(200000000)
	current := int64(1617695917476)
	expire := int64(1617695976000)
	ss, _, ff, tt, time, ee := UnsignedRaw1(from, to, amount, blockBytes, blockHash, current, expire)

	fmt.Println("temp=", ss)
	xpvk := pvk.String()

	fmt.Println("raw结果：", ss)

	b_s, _ := hex.DecodeString(ss)

	res, _, txid := SignedRaw1(b_s, xpvk)
	fmt.Println("签名结果：", res)

	url := "https://api.shasta.trongrid.io/wallet/broadcasttransaction"

	client := g.Client()

	param := g.Map{
		"txID": txid,
		"raw_data": g.Map{
			"contract": [...]g.Map{{
				"parameter": g.Map{
					"value": g.Map{
						"amount":        amount,
						"owner_address": ff,
						"to_address":    tt,
					},
					"type_url": "type.googleapis.com/protocol.TransferContract",
				},
				"type": "TransferContract",
			},
			},
			"ref_block_bytes": "9c50",
			"ref_block_hash":  "22b0f76cf489bad8",
			"expiration":      ee,
			"timestamp":       time,
		},
		"raw_data_hex": ss,
		"signatrure": res,
	}

	j, _ := json.Marshal(param)
	js := string(j)
	fmt.Printf("参数=%#v\n", js)
	r, _ := client.Post(url, js)
	defer r.Close()
	s := r.ReadAllString()
	fmt.Println("完成结果：", s)

	message := gjson.Get(s, "message")
	m, _ := hex.DecodeString(message.String())

	fmt.Printf("广播结果=%#v\n", string(m))
}

// 广播
func broad(from string, to string, blockBytes string, blockHash string, amount int64, current int64, expire int64) {
	fmt.Println("\n######################################## SignedRaw ########################################")
	mnemonic := "owner mosquito uphold xx xx xx xx xx vital chapter shoulder horn"  // 替换你的助记词
	seed, _ := bip39.NewSeed(mnemonic, "")
	pvk, _ := bip32.NewMaster(seed, HDPrivateKeyID)
	ss, _, ff, tt, time, ee := UnsignedRaw1(from, to, amount, blockBytes, blockHash, current, expire)

	fmt.Println("temp=", ss)
	xpvk := pvk.String()

	fmt.Println("raw结果：", ss)

	b_s, _ := hex.DecodeString(ss)

	res, _, txid := SignedRaw(b_s, xpvk)
	fmt.Println("签名结果：", res)

	//url := "https://api.shasta.trongrid.io/wallet/broadcasttransaction"
	url := "https://api.nileex.io/wallet/broadcasttransaction"

	client := g.Client()
	client.SetHeaderMap(map[string]string{
		"content-type": "json/application",
	})

	param := g.Map{
		"txID": txid,
		"raw_data": g.Map{
			"contract": [...]g.Map{{
				"parameter": g.Map{
					"value": g.Map{
						"amount":        amount,
						"owner_address": ff,
						"to_address":    tt,
					},
					"type_url": "type.googleapis.com/protocol.TransferContract",
				},
				"type": "TransferContract",
			},
			},
			"ref_block_bytes": blockBytes,
			"ref_block_hash":  blockHash,
			"expiration":      ee,
			"timestamp":       time,
		},
		"raw_data_hex": ss,
		//"signatrure":"6339ed0253074da5a8fffe391bf65978e9c33451d4cc3eff99abb1cd10d495f9ecd3c452b938570bb33af02f0cf984454eaa577d7fc7df2df36734ff6804fdd600",
		"signature": res,
		"visible":   false,
	}

	fmt.Println("计算signature=", res)
	fmt.Println("正确signature=", "6339ed0253074da5a8fffe391bf65978e9c33451d4cc3eff99abb1cd10d495f9ecd3c452b938570bb33af02f0cf984454eaa577d7fc7df2df36734ff6804fdd600")

	j, _ := json.Marshal(param)
	js := string(j)
	fmt.Printf("参数=%#v\n", js)
	r, _ := client.Post(url, js)
	defer r.Close()
	s := r.ReadAllString()
	fmt.Println("完成结果：", s)

	message := gjson.Get(s, "message")
	m, _ := hex.DecodeString(message.String())

	fmt.Printf("广播结果=%#v\n", string(m))
}

func TestProcessBH(t *testing.T) {
	s := "Num:13802595,ID:0000000000d980b21095c340ce3d2cf408986409572a732cfc54d10b24d21661"
	x := processBlockHeight(s)
	bytes := gconv.Bytes(x)

	fmt.Println(hex.EncodeToString(bytes))
}

func processBlockHeight(block string) int64 {
	num := strings.Split(block, ",")[0]
	heights := strings.Split(num, ":")
	if len(heights) < 1 {
		return 0
	}
	height, _ := strconv.ParseInt(heights[1], 10, 64)
	return height
}

// 测试创建新交易并广播
func TestBroad(t *testing.T) {
	from := "TGidpQoA6dcFkuroitVi3kwdsdYdUdQ9zX"
	to := "TUhTjVtigt3oYFaSWLWQp2XC5FJBN26G1J"
	amount := int64(200000000)
	current := time.Now().Unix() * 1000
	// 获取最新快
	c := g.Client()
	//r, _ := c.Get("https://api.shasta.trongrid.io/wallet/getnowblock")
	r, _ := c.Get("https://api.nileex.io/wallet/getnowblock")
	g := r.ReadAllString()
	// 整理参数构建blockHeader,获取blockBytes & blockHash
	txtireroot := gjson.Get(g, "block_header.raw_data.txTrieRoot").String()
	ttr, e := hex.DecodeString(txtireroot)
	if e != nil {
		glog.Error(e)
	}
	parentHash := gjson.Get(g, "block_header.raw_data.parentHash").String()
	ph, e := hex.DecodeString(parentHash)
	if e != nil {
		glog.Error(e)
	}
	witnessAddress := gjson.Get(g, "block_header.raw_data.witness_address").String()
	wA, e := hex.DecodeString(witnessAddress)
	if e != nil {
		glog.Error(e)
	}
	// 构建blockHeaderRaw 用于protocol序列化
	bhr := &protocol.BlockHeaderRaw{
		Timestamp:        gjson.Get(g, "block_header.raw_data.timestamp").Int(),
		TxTrieRoot:       ttr,
		ParentHash:       ph,
		Number:           gjson.Get(g, "block_header.raw_data.number").Int(),
		WitnessId:        0,
		WitnessAddress:   wA,
		Version:          20,
		AccountStateRoot: nil,
	}
	// 获取blockBytes
	s := gconv.Bytes(bhr.GetNumber())
	fmt.Println("block Number=", gconv.Uint32(s))
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b, gconv.Uint32(s))
	blockBytes := hex.EncodeToString(b[2:4])
	// expire
	expire := bhr.GetTimestamp() + 20000
	// 获取blockHash
	d, _ := proto.Marshal(bhr)
	h256 := sha256.New()
	h256.Write(d)
	bh := h256.Sum(nil)
	blockHash := hex.EncodeToString(bh[8:16])
	// 广播
	broad(from, to, blockBytes, blockHash, amount, current, expire)
}
