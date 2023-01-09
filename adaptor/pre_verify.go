package adaptor

import (
	"math/big"
	"sm2/normal"
	"sm2/util"
)

func PreVerifyToRS(digest *big.Int, sig *PreSignature, pub *normal.PublicKey) bool {
	intOne := new(big.Int).SetInt64(1)
	if sig.R.Cmp(intOne) == -1 || sig.R.Cmp(pub.Curve.N) >= 0 {
		return false
	}
	if sig.S.Cmp(intOne) == -1 || sig.S.Cmp(pub.Curve.N) >= 0 {
		return false
	}

	intZero := new(big.Int).SetInt64(0)
	rAdds := util.Add(sig.R, sig.S)
	rAdds = util.Mod(rAdds, pub.Curve.N)
	if rAdds.Cmp(intZero) == 0 {
		return false
	}

	sgx, sgy := pub.Curve.ScalarBaseMult(sig.S.Bytes())
	rAddsMultpx, rAddsMultpy := pub.Curve.ScalarMult(pub.X, pub.Y, rAdds.Bytes())
	kx, ky := pub.Curve.Add(sgx, sgy, rAddsMultpx, rAddsMultpy)
	if util.IsEcPointInfinity(kx, ky) {
		return false
	}

	kAddqx, kAddqy := pub.Curve.Add(kx, ky, sig.Q.X, sig.Q.Y)
	if util.IsEcPointInfinity(kAddqx, kAddqy) {
		return false
	}

	expectedR := util.Add(digest, kAddqx)
	expectedR = util.Mod(expectedR, pub.Curve.N)

	return expectedR.Cmp(sig.R) == 1
}

func PreVerify(msg, sig, pub string) bool {
	digest := normal.MsgToDigest(msg)
	presign := StringToPreSign(sig)
	publickey := normal.PubToPublicKey(pub)
	result := PreVerifyToRS(digest, presign, publickey)
	return result
}
