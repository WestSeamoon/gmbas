package adaptor

import (
	"fmt"
	"math/big"
	"sm2/normal"
)

// 预签名结构
type PreSignature struct {
	R, S *big.Int
	Q    *Point
}

// type Difficult struct {
// 	Y     Point
// 	y     *big.Int
// 	Curve normal.P256V1Curve
// }

type Point struct {
	X, Y  *big.Int
	Curve normal.P256V1Curve
}

// 字符串转点
func StringToPoint(s string) *Point {
	p := new(Point)
	p.Curve = normal.GetSm2P256V1()
	len := len(s) / 2
	x := s[:len]
	y := s[len:]
	// pub.X = StringToBigint(x)
	// pub.Y = StringToBigint(y)
	p.X = normal.StringToBigint(x)
	p.Y = normal.StringToBigint(y)
	return p
}

// 点转字符串
func PointToString(point *Point) string {
	px := normal.BigintToString(point.X)
	py := normal.BigintToString(point.Y)
	p_s := fmt.Sprintf("%s%s", px, py)
	return p_s
}

// 点转[]byte
func PointToBytes(point *Point) []byte {
	px_bytes := normal.BigintToByte(point.X)
	py_bytes := normal.BigintToByte(point.Y)
	point_bytes := append(px_bytes, py_bytes...)
	return point_bytes
}

// 预签名格式化
func StringToPreSign(sig string) *PreSignature {
	rs := sig[:len(sig)/2]
	q := sig[len(sig)/2:]
	r := rs[:len(rs)/2]
	s := rs[len(rs)/2:]
	qx := q[:len(rs)/2]
	qy := q[len(rs)/2:]
	presign := new(PreSignature)
	presign.Q = new(Point)
	presign.R = normal.StringToBigint(r)
	presign.S = normal.StringToBigint(s)
	presign.Q.X = normal.StringToBigint(qx)
	presign.Q.Y = normal.StringToBigint(qy)
	presign.Q.Curve = normal.GetSm2P256V1()
	return presign
}
