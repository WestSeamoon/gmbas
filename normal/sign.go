package normal

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"sm2/util"
)

// 普通SM2签名计算
func SignByRS(priv *PrivateKey, digest *big.Int) (sig *Sm2Signature, err error) {
	//pubX, pubY := priv.Curve.ScalarBaseMult(priv.D.Bytes())
	intZero := new(big.Int).SetInt64(0)
	intOne := new(big.Int).SetInt64(1)
	sig = new(Sm2Signature)
	for {
		var k *big.Int
		var err error
		for {
			k, err = NextK(rand.Reader, priv.Curve.N)
			if err != nil {
				return sig, err
			}
			kx, _ := priv.Curve.ScalarBaseMult(k.Bytes()) //K=kG
			sig.R = util.Add(digest, kx)                  //H(m)+f(K)
			sig.R = util.Mod(sig.R, priv.Curve.N)

			if sig.R.Cmp(intZero) != 0 {
				break
			}
		}

		dPlus1 := util.Add(priv.D, intOne) //1+d
		sig.S = util.Mul(sig.R, priv.D)    //rd
		sig.S = util.Sub(k, sig.S)         //k-rd
		sig.S = util.Mul(dPlus1, sig.S)    //(1+d)(k-rd)? should be (k-rd)/(1+d)
		sig.S = util.Mod(sig.S, priv.Curve.N)

		if sig.S.Cmp(intZero) != 0 {
			break
		}
	}

	return sig, nil
}

// 将签名结果转换为string
func Sm2_Sign(msg, priv string) (string, error) {
	privateKey := PrivToPrivateKey(priv)
	digest := MsgToDigest(msg)
	sig, err := SignByRS(privateKey, digest)
	if err != nil {
		return "", err
	}
	r_bytes := sig.R.Bytes()
	s_bytes := sig.S.Bytes()
	sig_bytes := append(r_bytes, s_bytes...)
	sign := hex.EncodeToString(sig_bytes)

	return sign, nil

}
