package smallcurve

import (
	"math/rand"
	"testing"
)

func TestModmul(t *testing.T) {
	if modmul(2, 3, 5) != 1 {
		t.Fail()
	}
	if modmul(2, 3, 6) != 0 {
		t.Fail()
	}
}

func TestModexp(t *testing.T) {
	var expected [][]uint64 = [][]uint64{
		{1, 0, 5, 1},
		{2, 0, 5, 1},
		{2, 1, 5, 2},
		{2, 2, 5, 4},
		{2, 3, 5, 3},
		{0x037a7e95e6abf6, 2, 0x0388cde6d6a9eb, 0x13a358525d8c7},
	}
	for _, e := range expected {
		x := e[0]
		y := e[1]
		m := e[2]
		expected := e[3]
		actual := modexp(x, y, m)
		t.Logf("%v^%v mod %v = %v (got %v)\n", x, y, m, expected, actual)
		if actual != expected {
			t.Fail()
		}
	}

}

func TestModSqrt(t *testing.T) {
	if ModSqrt(5, 41) != 28 {
		t.Fail()
	}
}

func TestC50(t *testing.T) {
	g := C50Parameters.G()
	if !g.verify() {
		t.Logf("G is not on the curve\n")
		t.Fail()
	}

	calculatedG := C50Parameters.Point(g.X(), g.Y()%2 == 1)
	if !g.Equals(calculatedG) {
		t.Errorf("Generator point y is not equivelent to computed y")
	}

	a := rand.Uint64() % C50Parameters.p
	b := rand.Uint64() % C50Parameters.p

	A := C50Parameters.G().Multiply(a)
	B := C50Parameters.G().Multiply(b)

	As := B.Multiply(a)
	Bs := A.Multiply(b)

	t.Logf("As: %v\n", As)
	t.Logf("Bs: %v\n", Bs)
	if !As.Equals(Bs) {
		t.Logf("As != Bs\n")
		t.Fail()
	}

}

func TestTiny(t *testing.T) {
	g := tinyParameters.G()
	if !g.verify() {
		t.Logf("G is not on the curve\n")
		t.Fail()
	}

	a := rand.Uint64() % tinyParameters.p
	b := rand.Uint64() % tinyParameters.p

	A := tinyParameters.G().Multiply(a)
	B := tinyParameters.G().Multiply(b)

	As := B.Multiply(a)
	Bs := A.Multiply(b)

	t.Logf("g * a (%v) = A (%v)\n", a, A)
	t.Logf("g * b (%v) = B (%v)\n", b, B)

	t.Logf("A * b (%v) = As (%v)\n", b, As)
	t.Logf("B * a (%v) = Bs (%v)\n", a, Bs)

	if !As.Equals(Bs) {
		t.Logf("As != Bs\n")
		t.Fail()
	}
}
