package adaptor

import (
	"encoding/hex"
	"math/big"
	"sm2/normal"
	"sm2/util"
)

func AdaptorBySy(presig *PreSignature, y *big.Int) (sig *normal.Sm2Signature) {
	sig = new(normal.Sm2Signature)
	sig.S = util.Add(presig.S, y)
	//sig.S = util.Mod(s, presig.Q.Curve.N)
	sig.R = presig.R

	return sig
}

func Adaptor(presig, y string) string {
	pre_sig := StringToPreSign(presig)
	yBigInt := normal.StringToBigint(y)
	s := AdaptorBySy(pre_sig, yBigInt)

	r_bytes := normal.BigintToByte(s.R)
	s_bytes := normal.BigintToByte(s.S)

	sig_bytes := append(r_bytes, s_bytes...)
	sig := hex.EncodeToString(sig_bytes)

	return sig
}
