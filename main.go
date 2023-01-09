package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"sm2/adaptor"
	"sm2/normal"
)

func main() {
	//tran_test1()
	//generatekey_test()
	//ecc_test()
	//sign_test()
	//verify_test()
	//presign_test()
	//preverify_test()
	//adaptor_test()
	//extract_test()
	for {
		fmt.Println("请选择您的需求：")
		fmt.Println("1.生成密钥对")
		fmt.Println("2.生成sm2签名")
		fmt.Println("3.验证sm2签名")
		fmt.Println("4.生成困难关系对")
		fmt.Println("5.生成预签名")
		fmt.Println("6.验证预签名")
		fmt.Println("7.预签名适配为sm2签名")
		fmt.Println("8.提取困难关系证据")
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
			fmt.Println(msg, "的SM2签名为:\n", sign)
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
		case 4:
			y, Y, _ := normal.GenerateKey(rand.Reader)
			fmt.Println("生成的困难关系对为：")
			fmt.Println("困难关系证据y:", y)
			fmt.Println("困难关系状态Y:", Y)
		case 5:
			var pri, msg, Y string
			fmt.Println("请输入需要签名的内容：")
			fmt.Scanln(&msg)
			fmt.Println("请输入困难关系状态")
			fmt.Scanln(&Y)
			fmt.Println("请输入私钥：")
			fmt.Scanln(&pri)
			sign, err := adaptor.PreSign(msg, Y, pri)
			if err != nil {
				fmt.Println(err)
			}
			fmt.Println(msg, "的SM2预签名为:\n", sign)
		case 6:
			var msg, sig, pub string
			fmt.Println("请输入消息内容：")
			fmt.Scanln(&msg)
			fmt.Println("请输入预签名：")
			fmt.Scanln(&sig)
			fmt.Println("请输入公钥：")
			fmt.Scanln(&pub)
			ver := adaptor.PreVerify(msg, sig, pub)
			fmt.Println("验证结果为:", ver)
		case 7:
			var pre_sig, y string
			fmt.Println("请输入预签名：")
			fmt.Scanln(&pre_sig)
			fmt.Println("请输入困难关系证据")
			fmt.Println(&y)
			adapt := adaptor.Adaptor(pre_sig, y)
			fmt.Println("适配的sm2签名为:\n", adapt)
		case 8:
			var pre_sig, sig string
			fmt.Println("请输入预签名:")
			fmt.Scanln(&pre_sig)
			fmt.Println("请输入sm2签名:")
			fmt.Scanln(&sig)
			extract_y := adaptor.Extract(sig, pre_sig)
			fmt.Println("提取到的困难关系证据y为:\n", extract_y)
		default:
			fmt.Println("请输入合法的数字！")
		}
	}

}
