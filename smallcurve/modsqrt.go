package smallcurve

import (
	"fmt"
	"math/bits"
)

func Jacobi(n, k uint64) int {
	if k%2 == 0 {
		panic("Jacobi: k must be odd")
	}
	n %= k
	t := 1
	for n != 0 {
		for n%2 == 0 {
			n /= 2
			r := k % 8
			if r == 3 || r == 5 {
				t = -t
			}
		}
		n, k = k, n
		if n%4 == 3 && k%4 == 3 {
			t = -t
		}
		n %= k
	}
	if k == 1 {
		return t
	}
	return 0
}

func modmul(x, y, m uint64) uint64 {
	hi, lo := bits.Mul64(x, y)
	r := bits.Rem64(hi, lo, m)
	return r
}

// Uses Euler's theorem to find the modular inverse of x modulo p
// Assumes p is prime
func modinvprime(x, p uint64) uint64 {
	phi := p - 1
	return modexp(x, phi-1, p)
}

func modsum(m uint64, terms ...uint64) uint64 {
	var hi, lo uint64
	for _, num := range terms {
		var carry uint64
		lo, carry = bits.Add64(lo, num, 0)
		hi += carry
	}
	//fmt.Printf("hi: %d, lo: %d\n", hi, lo)
	r := bits.Rem64(hi, lo, m)
	return r
}

func modsub(x, y, m uint64) uint64 {
	if x < y {
		return m - (y - x)
	}
	return x - y
}

func modexp(x, y, m uint64) uint64 {
	z := uint64(1)
	xprime := x % m
	for y > 0 {
		if y%2 == 1 {
			z = modmul(z, xprime, m)
		}
		xprime = modmul(xprime, xprime, m)
		y /= 2
	}
	return z
}

// Implements Tonnelli-Shanks algorithm to find a square root of a modulo p
func ModSqrt(n, p uint64) uint64 {
	if modexp(n, (p-1)/2, p) != 1 {
		panic(fmt.Sprintf("n (%v) is not a quadratic residue modulo p (%v)", n, p))
	}

	//fmt.Printf("n: %d, p: %d\n", n, p)
	p1 := p - 1
	// Find Q and S such that p - 1 = Q * 2^S with Q odd
	Q := p1 / 2
	S := uint64(1)
	for Q%2 == 0 {
		Q /= 2
		S++
	}
	//fmt.Printf("Q: %d, S: %d\n", Q, S)

	// Find a non-residue modulo p
	z := uint64(2)
	for Jacobi(z, p) != -1 {
		z++
	}
	//fmt.Printf("z: %d\n", z)

	// Initialize variables
	M := S
	c := modexp(z, Q, p)
	t := modexp(n, Q, p)
	R := modexp(n, (Q+1)/2, p)
	//fmt.Printf("Initial M: %d, c: %d, t: %d, R: %d\n", M, c, t, R)
	for !(t == 0 || t == 1) {
		//fmt.Printf("M: %d, c: %d, t: %d, R: %d\n", M, c, t, R)
		t2 := modexp(t, 2, p)
		i := uint64(1)
		for !(modexp(t2, i, p) == 1) {
			i++
		}
		if !(i < M) {
			panic(fmt.Sprintf("i (%v) >= M (%v)", i, M))
		}
		b := modexp(c, modexp(2, M-i-1, p), p)
		//fmt.Printf("i: %d, b: %d\n", i, b)
		M = i
		c = modexp(b, 2, p)
		t = modmul(t, c, p)
		R = modmul(R, b, p)
	}
	if t == 1 {
		//fmt.Printf("Final result: %d\n", R)
		return R
	}
	// t == 0
	return 0

}
