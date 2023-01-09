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
	"sm2/adaptor"
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

// 预签名测试
func presign_test() {
	test_d := "5DD701828C424B84C5D56770ECF7C4FE882E654CAC53C7CC89A66B1709068B9D"
	test_msg := "helloworld"
	test_Y := "05786df292aaa107b3467c6ff99f4e2f51f0dccccdee716e061c2720d0785f0f01e065995e22d4e647f8d9083c17905f2e19982a10495239060f07c949b72df6"
	test_presign, _ := adaptor.PreSign(test_msg, test_Y, test_d)
	fmt.Println(test_presign)
}

// 预签名验证测试
func preverify_test() {
	test_msg := "helloworld"
	test_presign := "0b2074396804f59e6cb11fffe6158d8b8206dda1d71b12c45ae7bb3b7ef8257aeb4d695b5509334a98df7cd1bb1ca46d3f4fb3c39b3beacee432e6a13165df6246b4ad444f264ccdd86378ac4763ca2fcf14780a2142f571b788ff33abdc2b8cff388212b2370f0c26e1fd059b5268b99546d9a245147858a6ce0f710e588836"
	test_pub := "FF6712D3A7FC0D1B9E01FF471A87EA87525E47C7775039D19304E554DEFE0913F632025F692776D4C13470ECA36AC85D560E794E1BCCF53D82C015988E0EB956"
	test_preverify := adaptor.PreVerify(test_msg, test_presign, test_pub)
	fmt.Println(test_preverify)
}

// 适配测试
func adaptor_test() {
	test_y := "166e312d1265863b2ffb589a8294214983d5a3d345416cdf1d978897ff11e839"
	test_presign := "4227ee599310586e7ed9264aaf7db844a78edd16c3d054e228d0fdbffe6403d38b528d6001a29ea260dfe5792620aa20317def105c661003dc5cb1259e9539630fd0948d3a974dc97e523ed911706d19c863d94362a5922502c398304cd7ec3f3f81a9110af025a962576e47a11e6fadc0e216da6d42d84925a9a8d910d799ff"
	test_adaptor := adaptor.Adaptor(test_presign, test_y)
	fmt.Println(test_adaptor)
}

// 提取测试
func extract_test() {
	test_presign := "4227ee599310586e7ed9264aaf7db844a78edd16c3d054e228d0fdbffe6403d38b528d6001a29ea260dfe5792620aa20317def105c661003dc5cb1259e9539630fd0948d3a974dc97e523ed911706d19c863d94362a5922502c398304cd7ec3f3f81a9110af025a962576e47a11e6fadc0e216da6d42d84925a9a8d910d799ff"
	test_sign := "4227ee599310586e7ed9264aaf7db844a78edd16c3d054e228d0fdbffe6403d3a1c0be8d140824dd90db3e13a8b4cb69b55392e3a1a77ce2f9f439bd9da7219c"
	test_exacty := adaptor.Extract(test_sign, test_presign)
	fmt.Println(test_exacty)
}
