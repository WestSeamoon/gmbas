package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"sm2/normal"
)

func main() {
	//tran_test1()
	//generatekey_test()
	//ecc_test()
	//sign_test()
	//verify_test()
	for {
		fmt.Println("请选择您的需求：")
		fmt.Println("1.生成密钥对")
		fmt.Println("2.生成签名")
		fmt.Println("3.验证签名")
		fmt.Println("0.退出")
		var require int
		fmt.Scanln(&require)
		//fmt.Println(require)
		switch require {
		case 0:
			os.Exit(-1)
		case 1:
			pri, pub, _ := normal.GenerateKey(rand.Reader)
			fmt.Println("生成的密钥对为：")
			fmt.Println("私钥：", pri)
			fmt.Println("公钥：", pub)
		case 2:
			var pri, msg string
			fmt.Println("请输入需要签名的内容：")
			fmt.Scanln(&msg)
			fmt.Println("请输入私钥：")
			fmt.Scanln(&pri)
			sign, err := normal.Sm2_Sign(msg, pri)
			if err != nil {
				fmt.Println(err)
			}
			fmt.Println(msg, "的SM2签名为:", sign)
		case 3:
			var msg, sig, pub string
			fmt.Println("请输入消息内容：")
			fmt.Scanln(&msg)
			fmt.Println("请输入签名：")
			fmt.Scanln(&sig)
			fmt.Println("请输入公钥：")
			fmt.Scanln(&pub)
			ver := normal.Verify(msg, sig, pub)
			fmt.Println("验证结果为:", ver)
		default:
			fmt.Println("请输入合法的数字！")
		}
	}

}
