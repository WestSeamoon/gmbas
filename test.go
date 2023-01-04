package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"os"
	"sm2/normal"
)

// 取hash测试
func hans_test2() {
	//方式一
	var date1 []byte = []byte("adfkfjsadsijfal")
	var hs = sha256.Sum256(date1)
	fmt.Printf("%X\n", hs)

	//方式二
	h := sha256.New()
	h.Write([]byte("adfkfjsadsijfal"))
	fmt.Printf("%X\n", h.Sum(nil))

	//方式三 从文件读取
	ha := sha256.New()
	f, err := os.Open("hash.test")
	if err != nil {
		fmt.Println("error1!")
	}
	defer f.Close()
	if _, err := io.Copy(ha, f); err != nil {
		fmt.Println("error2")
	}
	fmt.Printf("%X", ha.Sum(nil))
}

// 乱七八糟的数据类型转换测试
func tran_test1() {
	test_d := "5DD701828C424B84C5D56770ECF7C4FE882E654CAC53C7CC89A66B1709068B9D"
	test_ss, _ := new(big.Int).SetString(test_d, 16)
	test, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16) //将十六进制转换为大数
	test_dbyte, _ := hex.DecodeString(test_d)                                                                 //将十六进制解码为byte数组
	testset := new(big.Int).SetBytes(test_dbyte)                                                              //将byte数组转换为大数
	testhex := hex.EncodeToString(test_dbyte)                                                                 //将byte数组转换为hex
	var i int64 = 1
	testint := new(big.Int).SetInt64(i) //64位整数转大数
	fmt.Println(test_ss, "\n", test, "\n", test_dbyte, "\n", testset, "\n", testhex, "\n", testint)
	sm2P256V1 := normal.GetSm2P256V1().Gx
	test_a, test_b, _ := normal.GenerateKey(rand.Reader) //生成公私钥
	curve := normal.GetSm2P256V1()                       //生成sm2所用椭圆曲线
	curve_x := curve.Params().Gx
	fmt.Println(test_a, "\n", test_b, "\n", curve_x, "\n", sm2P256V1)
	sign_test()
	s := "abcd"
	len := len(s) / 2
	testx := s[:len]
	fmt.Println(len, testx)

	//测试用test.Bytes将大数转为[]byte与用hex.DecodeString转换结果是否一致
	byte1, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
	byte2 := byte1.Bytes()
	byte3, _ := hex.DecodeString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF")
	fmt.Println(byte2, "\n", byte3)
	//big := new(big.Int).SetBytes(byte3)
	//fmt.Println(byte1)
	//fmt.Println(big)
	byte4, _ := asn1.Marshal(byte1)
	fmt.Println(byte4)

}

// Key生成测试
func generatekey_test() {
	test_pri, test_pub, _ := normal.GenerateKey(rand.Reader) //生成公私钥
	fmt.Println(test_pri, test_pub)
}

func ecc_test() {
	fmt.Println(normal.BigintToString(normal.GetSm2P256V1().P))
	fmt.Println(normal.BigintToString(normal.GetSm2P256V1().A))
	fmt.Println(normal.BigintToString(normal.GetSm2P256V1().B))
	fmt.Println(normal.BigintToString(normal.GetSm2P256V1().N))
	fmt.Println(normal.BigintToString(normal.GetSm2P256V1().Gx))
	fmt.Println(normal.BigintToString(normal.GetSm2P256V1().Gy))
	fmt.Println(normal.GetSm2P256V1().Name)

}

// 普通SM2签名测试
func sign_test() {
	test_d := "5DD701828C424B84C5D56770ECF7C4FE882E654CAC53C7CC89A66B1709068B9D"
	test_msg := "helloworld"
	test_sig, err := normal.Sm2_Sign(test_msg, test_d)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(test_sig)
}

// 普通SM2验证测试
func verify_test() {
	test_pub := "FF6712D3A7FC0D1B9E01FF471A87EA87525E47C7775039D19304E554DEFE0913F632025F692776D4C13470ECA36AC85D560E794E1BCCF53D82C015988E0EB956"
	test_msg := "helloworld"
	test_sign := "41429bf38bd65d7054fb0bf426708d37c2b58502b9ac85d1a4a4762b85d6287e0642cd0d4aa304e114728c6c1ca2b42aa00d87b4b39249da3ae0fb21a610fb6d"
	//test_r, test_verify := normal.Verify(test_pub, test_sign, test_msg)
	//r := normal.BigintToString(test_r)
	test_verify := normal.Verify(test_msg, test_sign, test_pub)
	fmt.Println(test_verify)

}
