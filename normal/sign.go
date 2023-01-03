package normal

import (
	"crypto/rand"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"sm2/util"
)

// 私钥格式化
func PrivToPrivateKey(priv string) *PrivateKey {
	d_bigint := StringToBigint(priv)
	var privateKey PrivateKey
	privateKey.D = d_bigint
	privateKey.Curve = GetSm2P256V1()
	return &privateKey
}

// 普通SM2签名计算
func SignByRS(priv *PrivateKey, digest *big.Int) (r, s *big.Int, err error) {
	//pubX, pubY := priv.Curve.ScalarBaseMult(priv.D.Bytes())
	intZero := new(big.Int).SetInt64(0)
	intOne := new(big.Int).SetInt64(1)
	for {
		var k *big.Int
		var err error
		for {
			k, err = nextK(rand.Reader, priv.Curve.N)
			if err != nil {
				return nil, nil, err
			}
			kx, _ := priv.Curve.ScalarBaseMult(k.Bytes())
			r = util.Add(digest, kx)
			r = util.Mod(r, priv.Curve.N)

			if r.Cmp(intZero) != 0 {
				break
			}
		}

		dPlus1ModN := util.Add(priv.D, intOne)
		s = util.Mul(r, priv.D)
		s = util.Sub(k, s)
		s = util.Mul(dPlus1ModN, s)
		s = util.Mod(s, priv.Curve.N)

		if s.Cmp(intZero) != 0 {
			break
		}
	}

	return r, s, nil
}

// 将签名结果转换为string
func Sm2_Sign(priv, msg string) (string, error) {
	privateKey := PrivToPrivateKey(priv)
	digest := MsgToDigest(msg)
	r, s, err := SignByRS(privateKey, digest)
	if err != nil {
		return "", err
	}
	sig_byte, err := asn1.Marshal(sm2Signature{r, s})
	if err != nil {
		return "", err
	}
	sig := hex.EncodeToString(sig_byte)

	return sig, nil

}
