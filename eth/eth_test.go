package eth

import (
	"fmt"
	"testing"
	"time"

	"e.coding.net/webees/library/hdwallet/bip32"
	"e.coding.net/webees/library/hdwallet/bip39"

	"github.com/gogf/gf/container/gmap"
)

func TestEth(t *testing.T) {
	fmt.Println("\n######################################## ETH ########################################")
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

func TestTeth(t *testing.T) {
	TEST = true
	fmt.Println("\n######################################## tETH ########################################")
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

/**
测试组装原始交易数据
rlp格式如下，参考总长度109(根据参数改变)：
f8=f7+len(0x62)
6b=len(总内容体)
80		=80+00        nonce  (为0 内容位取消)
84 		=80+len(gasprice)
gasprice
82      =80+len(gas)
gas
94      =80+len(to)
to
88      =80+len(value)
Value
80      = 80+00       data  (为0 内容位取消)
v      （1字节）
a0
s      （32字节）
a0
r      （32字节）
*/
// 未签名数据体，base58存储
func TestUnsignedRaw(t *testing.T) {
	fmt.Println("\n######################################## UnsignedRaw ########################################")
	to := "0x6AE879A9d764d5125e23237529946Fb398b88D3F"
	amount := "0xde0b6b3a7640000"
	nonce := uint64(0x07)
	gasLimit := uint64(0x5208)
	gasPrice := uint64(0x4a817c800)
	frIndex := 0
	s, _ := UnsignedRaw(frIndex, nonce, to, amount, gasLimit, gasPrice)
	// 4K1CagyJfGcZiwTBr9iwVPztDDXZsuSxX4MCfCzyKSaK26p6VGLBJRhAZL2w4ycNZxespjkoWQDCvv19SDCukySgd2xphAv4tuppk27pHveYPqzWYwmd4n9V16UmAbNZkNZUShjk3doTskFtK6sRt8G1vHH3uFgSeSPhsEjmAF1wYu8xTRRuCRpEiH8NM1RoQqBpA9KZJgL17DaYoSeexK9sDdgfmCwbyoWPKUqttg1pmzhw7Yg83xHy2K3fBGY
	fmt.Println("待签名数据:", s)
}

// 签名tx raw
func TestSignedRaw(t *testing.T) {
	TEST = true
	fmt.Println("\n######################################## SignedRaw ########################################")
	mnemonic := "owner mosquito uphold xx xx xx xx xx vital chapter shoulder horn"  // 替换你的助记词
	seed, _ := bip39.NewSeed(mnemonic, "")
	xpvk, _ := bip32.NewMaster(seed, HDPrivateKeyID)
	// 未签名的base58字符串
	unsigned := "4K1CagyJfGcZiwTBr9iwVPztDDXZsuSxX4MCfCzyKSaK26p6VGLBJRhAZL2w4ycNZxespjkoWQDCvv19SDCukySgd2xphAv4tuppk27pHveYPqzWYwmd4n9g6Q46V16UmAbNZkNZUShjk3doTskFtK6sRt8G1vHH3uFgSeSPhsEjmAF1wYu8xTRRuCRpEiH8NM1RoQqBpA9KZJgL17DaYoSeexK9sDdgfmCwbyoWPKUqttg1pmzhw7Yg83xHy2K3fBGY"
	// 签名后rlp序列化
	s, _ := SignedRaw(unsigned, xpvk.String())
	// 0xf86c078504a817c800825208946ae879a9d764d5125e23237529946fb398b88d3f880de0b6b3a7640000802aa0aa26721fad99c2f28fbfde522df3cd82c6168c19fcbb3a6842926d137ea55e1ea07ef4e98203b36151bb0aea262e00a1f7a95aaca40e926721a9332c8c19f1869e
	fmt.Println("已签名数据:", s)
}

// ERC20代币 transaction raw
func TestERC20unsignedRaw(t *testing.T) {
	fmt.Println("\n######################################## ERC20unsignedRaw ########################################")
	to := "0x6AE879A9d764d5125e23237529946Fb398b88D3F"
	token := "0x774f3dcb7623f5b78f65049a79f144bd7a133d12"
	amount := "0x4e20"
	nonce := uint64(8)
	gasLimit := uint64(51453)
	gasPrice := uint64(0x2540BE400)
	frIndex := 0
	s, _ := UnsignedRaw(frIndex, nonce, to, amount, gasLimit, gasPrice, token)
	fmt.Println("待签名数据:", s)
	TEST = true
	fmt.Println("\n######################################## Erc20 SignedRaw ########################################")
	xpvk := "xprv9s21ZrQH143K3YFpEoWtTFxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx18bG5MeBwm2KQCrwTMbM3V4qb1WvVcaygAp6WdVBL" // 替换助记词对应的私钥
	res, _ := SignedRaw(s, xpvk)
	// 期待输出：0xf8a9088502540be40082c8fd94774f3dcb7623f5b78f65049a79f144bd7a133d1280b844a9059cbb0000000000000000000000006ae879a9d764d5125e23237529946fb398b88d3f0000000000000000000000000000000000000000000000000000000000004e2029a07bd70c34fd724ebd44a520dfc82123bd9fb0140e1f85cc49a9cbb2d4339275c6a012d7e427bb558b8815327fdf0689b231be01c93f05d3782949585faac071ec4c
	fmt.Println("ERC20签名raw=", res)
}

// 测试Erc20中的data
func TestErc20data(t *testing.T) {
	fmt.Println("\n######################################## erc20data ########################################")
	to := "0x6AE879A9d764d5125e23237529946Fb398b88D3F"
	amount := "20000"
	data := erc20data(to, amount)
	// 期待输出：a9059cbb0000000000000000000000005fccd73329d70ef6d1df82c3d0aeb36ec4ce5da50000000000000000000000000000000000000000000000000000000000004e20
	fmt.Printf("ErcData=%02x\n", data)
}
