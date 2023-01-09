package adaptor

import (
	"math/big"
	"sm2/normal"
	"sm2/util"
)

func ExtractBySign(presig *PreSignature, sig *normal.Sm2Signature) *big.Int {

	y := util.Sub(sig.S, presig.S)

	return y
}

func Extract(sig, presig string) string {
	sign := normal.StringToSign(sig)
	presign := StringToPreSign(presig)

	extract_y := ExtractBySign(presign, sign)

	y := normal.BigintToString(extract_y)

	return y

}
