package adaptor

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"sm2/normal"
	"sm2/util"
)

// 预签名生成
func PreSignByRSQ(digest *big.Int, Y *Point, priv *normal.PrivateKey) (*PreSignature, error) {
	intZero := new(big.Int).SetInt64(0)
	intOne := new(big.Int).SetInt64(1)
	dPlus1 := util.Add(priv.D, intOne)
	//var preSign *PreSignature
	preSign := new(PreSignature)
	preSign.Q = new(Point)
	var err error
	preSign.Q.X, preSign.Q.Y = Y.Curve.ScalarMult(Y.X, Y.Y, dPlus1.Bytes())
	var zeroPoint, K, KQ *Point
	zeroPoint = new(Point)
	K = new(Point)
	KQ = new(Point)
	zeroPoint.X = intZero
	zeroPoint.Y = intZero
	for {
		var k *big.Int
		for {
			k, err = normal.NextK(rand.Reader, priv.Curve.N)
			if err != nil {
				return preSign, err
			}
			K.X, K.Y = priv.Curve.ScalarBaseMult(k.Bytes())
			KQ.X, _ = priv.Curve.Add(K.X, K.Y, preSign.Q.X, preSign.Q.Y)
			preSign.R = util.Add(digest, KQ.X)
			preSign.R = util.Mod(preSign.R, priv.Curve.N)

			if preSign.R.Cmp(intZero) != 0 {
				break
			}
		}
		preSign.S = util.Mul(preSign.R, priv.D)
		preSign.S = util.Sub(k, preSign.S)
		preSign.S = util.Mul(dPlus1, preSign.S)
		preSign.S = util.Mod(preSign.S, priv.Curve.N)

		if preSign.S.Cmp(intZero) != 0 {
			break
		}
	}
	return preSign, nil

}

// 预签名结果转换为string
func PreSign(msg, Y, priv string) (string, error) {
	digest := normal.MsgToDigest(msg)
	diffY := StringToPoint(Y)
	privateKey := normal.PrivToPrivateKey(priv)
	preSign, err := PreSignByRSQ(digest, diffY, privateKey)
	if err != nil {
		return "", err
	}
	r_bytes := preSign.R.Bytes()
	s_bytes := preSign.S.Bytes()
	q_bytes := PointToBytes(preSign.Q)
	rs_bytes := append(r_bytes, s_bytes...)
	sig_bytes := append(rs_bytes, q_bytes...)
	sig := hex.EncodeToString(sig_bytes)

	return sig, nil
}
