package normal

import (
	"math/big"
	"sm2/util"
)

// 签名分割为r和s，并转换为*big.Int类型
func StringToSign(sig string) (sign *Sm2Signature) {
	sign = new(Sm2Signature)
	len := len(sig) / 2
	r_string := sig[:len]
	s_string := sig[len:]
	// r = StringToBigint(r_string)
	// s = StringToBigint(s_string)
	sign.R = StringToBigint(r_string)
	sign.S = StringToBigint(s_string)
	return sign
}

// 验证核心代码，通过公钥，r和s，消息摘要进行验证
func VerifyByRS(pub *PublicKey, sig *Sm2Signature, digest *big.Int) bool {
	intOne := new(big.Int).SetInt64(1)
	if sig.R.Cmp(intOne) == -1 || sig.R.Cmp(pub.Curve.N) >= 0 {
		return false
	}
	if sig.S.Cmp(intOne) == -1 || sig.S.Cmp(pub.Curve.N) >= 0 {
		return false
	}

	intZero := new(big.Int).SetInt64(0)
	t := util.Add(sig.R, sig.S) //r+s
	t = util.Mod(t, pub.Curve.N)
	if t.Cmp(intZero) == 0 {
		return false
	}

	sgx, sgy := pub.Curve.ScalarBaseMult(sig.S.Bytes())       //sG
	tpx, tpy := pub.Curve.ScalarMult(pub.X, pub.Y, t.Bytes()) //(r+s)P
	x, y := pub.Curve.Add(sgx, sgy, tpx, tpy)
	if util.IsEcPointInfinity(x, y) {
		return false
	}

	expectedR := util.Add(digest, x) //H(m)+f(sG+(r+s)P)
	expectedR = util.Mod(expectedR, pub.Curve.N)
	return expectedR.Cmp(sig.R) == 1
}

// 验证参数格式化，调用验证代码返回true or false
func Verify(msg string, sig string, pub string) bool {
	publicKey := PubToPublicKey(pub)
	digest := MsgToDigest(msg)
	sign := StringToSign(sig)
	result := VerifyByRS(publicKey, sign, digest)
	return result
}
