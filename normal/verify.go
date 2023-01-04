package normal

import (
	"math/big"
	"sm2/util"
)

// 公钥格式化
func PubToPublicKey(s string) *PublicKey {
	pub := new(PublicKey)
	pub.Curve = GetSm2P256V1()
	len := len(s) / 2
	x := s[:len]
	y := s[len:]
	// pub.X = StringToBigint(x)
	// pub.Y = StringToBigint(y)
	pub.X = StringToBigint(x)
	pub.Y = StringToBigint(y)
	return pub
}

// 签名分割为r和s，并转换为*big.Int类型
func SignToRS(sig string) (r, s *big.Int) {
	len := len(sig) / 2
	r_string := sig[:len]
	s_string := sig[len:]
	// r = StringToBigint(r_string)
	// s = StringToBigint(s_string)
	r = StringToBigint(r_string)
	s = StringToBigint(s_string)
	return r, s
}

// 验证核心代码，通过公钥，r和s，消息摘要进行验证
func VerifyByRS(pub *PublicKey, r, s *big.Int, digest *big.Int) bool {
	intOne := new(big.Int).SetInt64(1)
	if r.Cmp(intOne) == -1 || r.Cmp(pub.Curve.N) >= 0 {
		return false
	}
	if s.Cmp(intOne) == -1 || s.Cmp(pub.Curve.N) >= 0 {
		return false
	}

	intZero := new(big.Int).SetInt64(0)
	t := util.Add(r, s)
	t = util.Mod(t, pub.Curve.N)
	if t.Cmp(intZero) == 0 {
		return false
	}

	sgx, sgy := pub.Curve.ScalarBaseMult(s.Bytes())
	tpx, tpy := pub.Curve.ScalarMult(pub.X, pub.Y, t.Bytes())
	x, y := pub.Curve.Add(sgx, sgy, tpx, tpy)
	if util.IsEcPointInfinity(x, y) {
		return false
	}

	expectedR := util.Add(digest, x)
	expectedR = util.Mod(expectedR, pub.Curve.N)
	return expectedR.Cmp(r) == 1
}

// 验证参数格式化，调用验证代码返回true or false
func Verify(msg string, sig string, pub string) bool {
	publicKey := PubToPublicKey(pub)
	digest := MsgToDigest(msg)
	r, s := SignToRS(sig)
	result := VerifyByRS(publicKey, r, s, digest)
	return result
}
