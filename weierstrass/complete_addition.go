package weierstrass

import (
	"math/big"
)

// Implements https://eprint.iacr.org/2015/1060.pdf

func modMul(a, b, p *big.Int) *big.Int {
	res := new(big.Int).Mul(a, b)
	res.Mod(res, p)
	return res
}


func modAdd(a, b, p *big.Int) *big.Int {
	res := new(big.Int).Add(a, b)
	res.Mod(res, p)
	return res
}



func modSub(a, b, p *big.Int) *big.Int {
	res := new(big.Int).Sub(a, b)
	res.Mod(res, p)
	return res
}

func addAlgorithm1(X1, Y1, Z1, X2, Y2, Z2 *big.Int, curveParams *CurveParams) (X3, Y3, Z3 *big.Int) {
	//  Algorithm 1: Complete, projective point addition for arbitrary prime order short
	//Weierstrass curves E/Fq : y2 = x3 + ax + b.
	//Require: P = (X1 : Y1 : Z1), Q = (X2 : Y2 : Z2), E : Y 2Z = X3 + aXZ2 + bZ3,
	// and b3 = 3 · b.
	//Ensure: (X3 : Y3 : Z3) = P + Q.]
	p := curveParams.p
	b3 := new(big.Int).Mul(big.NewInt(3), curveParams.b)
	a := curveParams.a

	mul := func(a, b *big.Int) *big.Int {
		return modMul(a, b, p)
	}
	add := func(a, b *big.Int) *big.Int {
		return modAdd(a, b, p)
	}
	sub := func(a, b *big.Int) *big.Int {
		return modSub(a, b, p)
	}

	// 1. t0 ← X1 · X2
	t0 := mul(X1, X2)

	// 2. t1 ← Y1 · Y2
	t1 := mul(Y1, Y2)

	// 3. t2 ← Z1 · Z2
	t2 := mul(Z1, Z2)

	// 4. t3 ← X1 + Y1
	t3 := add(X1, Y1)

	// 5. t4 ← X2 + Y2
	t4 := add(X2, Y2)

	// 6. t3 ← t3 · t4
	t3 = mul(t3, t4)

	// 7. t4 ← t0 + t1
	t4 = add(t0, t1)

	// 8. t3 ← t3 − t4
	t3 = sub(t3, t4)

	// 9. t4 ← X1 + Z1
	t4 = add(X1, Z1)

	// 10. t5 ← X2 + Z2
	t5 := add(X2, Z2)

	// 11. t4 ← t4 · t5
	t4 = mul(t4, t5)

	// 12. t5 ← t0 + t2
	t5 = add(t0, t2)

	// 13. t4 ← t4 − t5
	t4 = sub(t4, t5)

	// 14. t5 ← Y1 + Z1
	t5 = add(Y1, Z1)

	// 15. X3 ← Y2 + Z2
	X3 = add(Y2, Z2)

	// 16. t5 ← t5 · X3
	t5 = mul(t5, X3)

	// 17. X3 ← t1 + t2
	X3 = add(t1, t2)

	// 18. t5 ← t5 − X3
	t5 = sub(t5, X3)

	// 19. Z3 ← a · t4
	Z3 = mul(a, t4)

	// 20. X3 ← b3 · t2
	X3 = mul(b3, t2)

	// 21. Z3 ← X3 + Z3
	Z3 = add(X3, Z3)

	// 22. X3 ← t1 − Z3
	X3 = sub(t1, Z3)

	// 23. Z3 ← t1 + Z3
	Z3 = add(t1, Z3)

	// 24. Y3 ← X3 · Z3
	Y3 = mul(X3, Z3)

	// 25. t1 ← t0 + t0
	t1 = add(t0, t0)

	// 26. t1 ← t1 + t0
	t1 = add(t1, t0)

	// 27. t2 ← a · t2
	t2 = mul(a, t2)
	// 28. t4 ← b3 · t4
	t4 = mul(b3, t4)

	// 29. t1 ← t1 + t2
	t1 = add(t1, t2)

	// 30. t2 ← t0 − t2
	t2 = sub(t0, t2)

	// 31. t2 ← a · t2
	t2 = mul(a, t2)

	// 32. t4 ← t4 + t2
	t4 = add(t4, t2)

	// 33. t0 ← t1 · t4
	t0 = mul(t1, t4)

	// 34. Y3 ← Y3 + t0
	Y3 = add(Y3, t0)

	// 35. t0 ← t5 · t4
	t0 = mul(t5, t4)

	// 36. X3 ← t3 · X3
	X3 = mul(t3, X3)

	// 37. X3 ← X3 − t0
	X3 = sub(X3, t0)

	// 38. t0 ← t3 · t1
	t0 = mul(t3, t1)

	// 39. Z3 ← t5 · Z3
	Z3 = mul(t5, Z3)

	// 40. Z3 ← Z3 + t0
	Z3 = add(Z3, t0)

	return X3, Y3, Z3
}

func pointToProjective(P *Point) (X, Y, Z *big.Int) {
	if P.IsInfinity() {
		return big.NewInt(0), big.NewInt(1), big.NewInt(0)
	}
	return new(big.Int).Set(P.X()), new(big.Int).Set(P.Y()), big.NewInt(1)
}

func projectiveToPoint(X, Y, Z *big.Int, curveParams *CurveParams) *Point {
	p := curveParams.p
	if Z.Sign() == 0 {
		return &Point{curve: &Curve{params: curveParams}}
	}
	// Standard projective dehomogenization: x = X / Z, y = Y / Z
	zInv := new(big.Int).ModInverse(Z, p)
	if zInv == nil {
		panic("Z has no modular inverse")
	}
	x := modMul(X, zInv, p)
	y := modMul(Y, zInv, p)
	return &Point{curve: &Curve{params: curveParams}, x: x, y: y}
}

func completeAddAlgorithm1(P, Q *Point) *Point {

	X1, Y1, Z1 := pointToProjective(P)
	X2, Y2, Z2 := pointToProjective(Q)
	X3, Y3, Z3 := addAlgorithm1(X1, Y1, Z1, X2, Y2, Z2, P.curve.params)
	result := projectiveToPoint(X3, Y3, Z3, P.curve.params)

	return result
}
