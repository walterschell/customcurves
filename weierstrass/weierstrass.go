package weierstrass

// This package implements non-timing resistant generic weierstrass elliptic curves.
// In particular, it allows for generic A coefficients, where the golang standard library
// only supports A=-3.

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
)

const checkPointsAfterEveryAdd = true
const useCompleteAddition = true

var two = big.NewInt(2)
var three = big.NewInt(3)

type CurveParams struct {
	// Y^2 = X^3 + A*X + B mod P
	p    *big.Int // The prime modulus
	a    *big.Int
	b    *big.Int
	gx   *big.Int
	gy   *big.Int
	n    *big.Int // The order of the curve. Must be prime.
	name string
}

/*
Constructs a new curve with the following parameters

Y^2 = X^3 + A*x + B mod P
p prime modulus (must be prime)
a A value for curve
b B value for curve
gx Generator point x coordinate
gy Generator point y coordinate
n Order of curve (must be prime)
*/
func NewCurveParams(p, a, b, gx, gy, n, name string) (*CurveParams, error) {
	ip, ok := new(big.Int).SetString(p, 0)
	if !ok {
		return nil, fmt.Errorf("invalid Number for p: %s", p)
	}
	ia, ok := new(big.Int).SetString(a, 0)
	if !ok {
		return nil, fmt.Errorf("invalid Number for a: %s", a)
	}
	ib, ok := new(big.Int).SetString(b, 0)
	if !ok {
		return nil, fmt.Errorf("invalid Number for b: %s", b)
	}
	igx, ok := new(big.Int).SetString(gx, 0)
	if !ok {
		return nil, fmt.Errorf("invalid Number for gx: %s", gx)
	}
	igy, ok := new(big.Int).SetString(gy, 0)
	if !ok {
		return nil, fmt.Errorf("invalid Number for gy: %s", gy)
	}
	in, ok := new(big.Int).SetString(n, 0)
	if !ok {
		return nil, fmt.Errorf("invalid Number for n: %s", n)
	}

	if !ip.ProbablyPrime(20) {
		return nil, fmt.Errorf("invalid prime modulus")
	}
	if !in.ProbablyPrime(20) {
		return nil, fmt.Errorf("invalid order (not prime)")
	}
	if in.Cmp(ip) >= 0 {
		return nil, fmt.Errorf("invalid order (greater than modulus)")
	}
	if igx.Cmp(ip) >= 0 {
		return nil, fmt.Errorf("invalid base point")
	}
	if igy.Cmp(ip) >= 0 {
		return nil, fmt.Errorf("invalid base point")
	}

	return &CurveParams{
		p:    ip,
		a:    ia,
		b:    ib,
		gx:   igx,
		gy:   igy,
		n:    in,
		name: name,
	}, nil
}

/*
Constructs a new curve with the following parameters

Y^2 = X^3 + A*x + B mod P
p prime modulus (must be prime)
a A value for curve
b B value for curve
gx Generator point x coordinate
gy Generator point y coordinate
n Order of curve (must be prime)

do not modify any of the big.Int parameters after calling this function
*/
func NewCurveParamsFromBigInts(p, a, b, gx, gy, n *big.Int, name string) (*CurveParams, error) {
	if !p.ProbablyPrime(20) {
		return nil, fmt.Errorf("invalid prime modulus")
	}
	if !n.ProbablyPrime(20) {
		return nil, fmt.Errorf("invalid order (not prime)")
	}
	if n.Cmp(p) >= 0 {
		return nil, fmt.Errorf("invalid order (greater than modulus)")
	}
	if gx.Cmp(p) >= 0 {
		return nil, fmt.Errorf("invalid base point")
	}
	if gy.Cmp(p) >= 0 {
		return nil, fmt.Errorf("invalid base point")
	}

	return &CurveParams{
		p:    p,
		a:    a,
		b:    b,
		gx:   gx,
		gy:   gy,
		n:    n,
		name: name,
	}, nil

}

// P returns the prime modulus of the curve.
func (cp *CurveParams) P() *big.Int {
	return new(big.Int).Set(cp.p)
}

// A returns the coefficient A of the curve equation.
func (cp *CurveParams) A() *big.Int {
	return new(big.Int).Set(cp.a)
}

// B returns the coefficient B of the curve equation.
func (cp *CurveParams) B() *big.Int {
	return new(big.Int).Set(cp.b)
}

// Gx returns the x-coordinate of the base point G.
func (cp *CurveParams) Gx() *big.Int {
	return new(big.Int).Set(cp.gx)
}

// Gy returns the y-coordinate of the base point G.
func (cp *CurveParams) Gy() *big.Int {
	return new(big.Int).Set(cp.gy)
}

// N returns the order of the curve.
func (cp *CurveParams) N() *big.Int {
	return new(big.Int).Set(cp.n)
}

// Name returns the name of the curve.
func (cp *CurveParams) Name() string {
	return cp.name
}

// Equal compares two CurveParams for equality.
func (cp *CurveParams) Equal(other *CurveParams) bool {
	return cp == other || (cp.p.Cmp(other.p) == 0 &&
		cp.a.Cmp(other.a) == 0 &&
		cp.b.Cmp(other.b) == 0 &&
		cp.gx.Cmp(other.gx) == 0 &&
		cp.gy.Cmp(other.gy) == 0 &&
		cp.n.Cmp(other.n) == 0 &&
		cp.name == other.name)
}

// Returns the size in bits of the prime modulus.
func (cp *CurveParams) BitSize() int {
	return cp.p.BitLen()
}

func writeBigInt(writer io.Writer, value *big.Int) error {
	bytes := value.Bytes()
	sizeBytes := []byte{}
	sizeBytes = binary.AppendVarint(sizeBytes, int64(len(bytes)))
	_, err := writer.Write(sizeBytes)
	if err != nil {
		return err
	}

	_, err = writer.Write(bytes)
	if err != nil {
		return err
	}
	return nil

}

// Serialize CurveParams
func (cp *CurveParams) Write(writer io.Writer) error {
	err := writeBigInt(writer, cp.p)
	if err != nil {
		return err
	}
	err = writeBigInt(writer, cp.a)
	if err != nil {
		return err
	}
	err = writeBigInt(writer, cp.b)
	if err != nil {
		return err
	}
	err = writeBigInt(writer, cp.gx)
	if err != nil {
		return err
	}
	err = writeBigInt(writer, cp.gy)
	if err != nil {
		return err
	}
	err = writeBigInt(writer, cp.n)
	if err != nil {
		return err
	}
	_, err = writer.Write([]byte(cp.name))
	return err
}

// Compute fingerprint of curve for added sanity checks
func (cp *CurveParams) SHA256Digest() []byte {
	hash := sha256.New()
	cp.Write(hash)
	return hash.Sum(nil)
}

func readBigInt(reader io.Reader) (*big.Int, error) {
	byteReader, ok := reader.(io.ByteReader)
	if !ok {
		byteReader = bufio.NewReader(reader)
	}
	length, err := binary.ReadVarint(byteReader)
	if err != nil {
		return nil, err
	}
	bytes := make([]byte, length)
	_, err = reader.Read(bytes)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(bytes), nil
}

// Deserialize curve parameters
func ReadCurveParams(reader io.Reader) (*CurveParams, error) {
	p, err := readBigInt(reader)
	if err != nil {
		return nil, err
	}
	a, err := readBigInt(reader)
	if err != nil {
		return nil, err
	}
	b, err := readBigInt(reader)
	if err != nil {
		return nil, err
	}
	gx, err := readBigInt(reader)
	if err != nil {
		return nil, err
	}
	gy, err := readBigInt(reader)
	if err != nil {
		return nil, err
	}
	n, err := readBigInt(reader)
	if err != nil {
		return nil, err
	}
	nameBytes := make([]byte, 1024)
	sz, err := reader.Read(nameBytes)
	if err != nil {
		return nil, err
	}
	name := string(nameBytes[:sz])
	return &CurveParams{p, a, b, gx, gy, n, name}, nil
}

// Curve object for conducting math operations
type Curve struct {
	params *CurveParams
	g      *Point
}

// Equal compares two Curves for equality.
func (c *Curve) Equal(other *Curve) bool {
	return c == other || c.params.Equal(other.params)
}

// Returns parameters for a curve
func (c *Curve) Params() *CurveParams {
	return c.params
}

// Construct a Curve instance from CurveParams
func NewCurve(params *CurveParams) *Curve {
	return &Curve{params, nil}
}

// Construct a Curve instance from serialized curve parameters
func NewCurveBytes(serializedParams []byte) (*Curve, error) {
	reader := bytes.NewReader(serializedParams)
	params, err := ReadCurveParams(reader)
	if err != nil {
		return nil, err
	}
	return &Curve{params, nil}, nil
}

// Point on a Curve
type Point struct {
	x     *big.Int
	y     *big.Int
	curve *Curve
}

func (p *Point) String() string {
	if p.IsInfinity() {
		return fmt.Sprintf("[%v](Infinity)", p.curve.params.name)
	}
	return fmt.Sprintf("[%v](0x%x, 0x%x)", p.curve.params.name, p.x, p.y)
}

func (p *Point) Equals(other *Point) bool {
	if p == other {
		return true
	}
	if !p.curve.Equal(other.curve) {
		return false
	}
	if p.IsInfinity() && other.IsInfinity() {
		return true
	}
	if p.IsInfinity() || other.IsInfinity() {
		return false
	}
	return p.x.Cmp(other.x) == 0 && p.y.Cmp(other.y) == 0
}

func (p *Point) Curve() *Curve {
	return p.curve
}

// Returns X coordinate of the point.
func (p *Point) X() *big.Int {
	return new(big.Int).Set(p.x)
}

// Returns Y coordinate of the point.
func (p *Point) Y() *big.Int {
	return new(big.Int).Set(p.y)
}

// Compares the coordinates and curves of two points
// in particular two points that have otherwise the same
// x,y coords but that were derived from different curves will
// not compare equal.
func (p *Point) Equal(other *Point) bool {
	return p == other || (p.curve.Equal(other.curve) &&
		p.x.Cmp(other.x) == 0 &&
		p.y.Cmp(other.y) == 0)
}

// Tests if coordinates for a point are on a given curve
func (c *Curve) IsOnCurve(x, y *big.Int) bool {
	if x == nil || y == nil {
		return false
	}
	// y^2 = x^3 + ax + b
	y2 := new(big.Int).Exp(y, two, c.params.p)

	x3 := new(big.Int).Exp(x, three, c.params.p)

	ax := new(big.Int).Mul(c.params.a, x)
	ax.Mod(ax, c.params.p)

	x3.Add(x3, ax)
	x3.Add(x3, c.params.b)
	x3.Mod(x3, c.params.p)
	return y2.Cmp(x3) == 0
}

type NotOnCurveError struct {
}

func (e NotOnCurveError) Error() string {
	return "Point is not on the curve"
}

// If x, y coordinates are on the curve, returns
// a Point tied to those points
// do not modify x or y after calling this function
func (c *Curve) NewPoint(x, y *big.Int) (*Point, error) {
	if !c.IsOnCurve(x, y) {
		return nil, NotOnCurveError{}
	}
	return &Point{x, y, c}, nil
}

// If x is on the curve recover one of the two
// y coordinates determined by parity
// do not modify x after calling this function
func (c *Curve) NewPointCompressed(x *big.Int, parity byte) (*Point, error) {
	// y^2 = x^3 + ax + b
	x3 := new(big.Int).Exp(x, three, c.params.p)
	ax := new(big.Int).Mul(c.params.a, x)
	ax.Mod(ax, c.params.p)
	x3.Add(x3, ax)
	x3.Add(x3, c.params.b)
	rhs := x3.Mod(x3, c.params.p)

	// y = sqrt(x^3 + ax + b)
	y := new(big.Int).ModSqrt(rhs, c.params.p)
	if y == nil {
		return nil, NotOnCurveError{}
	}

	if y.Bit(0) != uint(parity&1) {
		y.Sub(c.params.p, y)
	}

	return c.NewPoint(x, y)
}

// Returns the generator point for a curve
func (c *Curve) G() *Point {
	if c.g == nil {
		g, err := c.NewPoint(c.params.gx, c.params.gy)
		if err != nil {
			panic("Invalid base point")
		}
		c.g = g
	}
	return c.g
}

// Represents the point at infinity
func (c *Curve) Infinity() *Point {
	return &Point{nil, nil, c}
}

// Tests if a point is the point at infinity
func (p *Point) IsInfinity() bool {
	return p.x == nil && p.y == nil
}

func (c *Curve) newKeyPair() (*Point, *big.Int, error) {
	for {
		k, err := rand.Int(rand.Reader, c.params.n)
		if err != nil {
			return nil, nil, err
		}
		pt := c.G().Mul(k)
		if !pt.IsInfinity() {
			return pt, k, nil
		}
	}
}

// Marshals a point
// Parity + X value + curve fingerprint
func (p *Point) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)
	if p.y.Bit(0) == 1 {
		buf.WriteByte(0x03)
	} else {
		buf.WriteByte(0x02)
	}
	err := writeBigInt(buf, p.x)
	if err != nil {
		return nil, err
	}

	buf.Write(p.curve.params.SHA256Digest())
	return buf.Bytes(), nil
}

// Unmarshals a point and sanity checks that it was for the
// selected curve and that it is on curve
func (c *Curve) UnmarshalPoint(data []byte) (*Point, error) {
	reader := bytes.NewReader(data)

	parity := make([]byte, 1)
	_, err := reader.Read(parity)
	if err != nil {
		return nil, err
	}
	x, err := readBigInt(reader)
	if err != nil {
		return nil, err
	}

	curveFingerprint := make([]byte, 32)
	_, err = reader.Read(curveFingerprint)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(c.params.SHA256Digest(), curveFingerprint) {
		fmt.Printf("Expected: %x\n", c.params.SHA256Digest())
		fmt.Printf("Got: %x\n", curveFingerprint)
		return nil, fmt.Errorf("Curve fingerprint does not match")
	}
	result, err := c.NewPointCompressed(x, parity[0])
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Secret key
// scalar associated with Curve
type Scalar struct {
	k     *big.Int
	curve *Curve
}

func (k *Scalar) String() string {
	return fmt.Sprintf("[%s] Scalar(%s)", k.curve.params.name, k.k.String())
}

// Compares two secret keys
func (lhs *Scalar) Equals(rhs *Scalar) bool {
	return lhs == rhs || (lhs.curve.Equal(rhs.curve) &&
		lhs.k.Cmp(rhs.k) == 0)
}

func (k *Scalar) Curve() *Curve {
	return k.curve
}

func (k *Scalar) K() *big.Int {
	return new(big.Int).Set(k.k)
}

// Marshals a secret key
// scalar + curve fingerprint
func (k *Scalar) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := writeBigInt(buf, k.k)
	if err != nil {
		return nil, err
	}
	buf.Write(k.curve.params.SHA256Digest())
	return buf.Bytes(), nil
}

// Unmarshals a secret key
// verifies it intended for the current curve and sanity checks it
func (c *Curve) UnmarshalScalar(data []byte) (*Scalar, error) {
	reader := bytes.NewReader(data)
	k, err := readBigInt(reader)
	if err != nil {
		return nil, err
	}
	curveFingerprint := make([]byte, 32)
	_, err = reader.Read(curveFingerprint)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(c.params.SHA256Digest(), curveFingerprint) {
		return nil, fmt.Errorf("curve fingerprint does not match")
	}
	if k.Cmp(c.params.n) >= 0 {
		return nil, fmt.Errorf("invalid secret key")
	}
	return &Scalar{k, c}, nil
}

// Returns the public key for a secret key
func (k *Scalar) Point() *Point {
	return k.curve.G().Mul(k.k)
}

// Generates a new keypair
func (c *Curve) NewKeypair() (*Point, *Scalar, error) {
	pub, k, err := c.newKeyPair()
	if err != nil {
		return nil, nil, err
	}
	return pub, &Scalar{k, c}, nil
}

// Adds two points
func (p *Point) Add(q *Point) *Point {
	if useCompleteAddition {
		result := completeAddAlgorithm1(p, q)
		if checkPointsAfterEveryAdd {
			if !result.IsInfinity() && !result.curve.IsOnCurve(result.x, result.y) {
				fmt.Printf("Result point: %s\n", result.String())
				panic("Point is not on the curve after complete addition")
			}
		}
		return result
	}

	if checkPointsAfterEveryAdd {
		if !p.IsInfinity() && !p.curve.IsOnCurve(p.x, p.y) {
			panic("Point is not on the curve")
		}
		if !q.IsInfinity() && !q.curve.IsOnCurve(q.x, q.y) {
			panic("Point is not on the curve")
		}
	}
	if !p.curve.Equal(q.curve) {
		panic("Points are not on the same curve")
	}
	if p.IsInfinity() {
		return q
	}
	if q.IsInfinity() {
		return p
	}
	shouldDouble := false
	if p.x.Cmp(q.x) == 0 && p.y.Cmp(q.y) != 0 {
		return p.curve.Infinity()
	} else if p.Equal(q) {
		shouldDouble = true
	}

	var slope *big.Int

	if shouldDouble {

		// Slope = (3*x^2 + a) / (2*y)
		numerator := new(big.Int).Mul(three,
			new(big.Int).Exp(p.x,
				two,
				p.curve.params.p))
		numerator.Add(numerator, p.curve.params.a)
		numerator.Mod(numerator, p.curve.params.p)

		denominator := new(big.Int).Mul(two, p.y)
		denominator.Mod(denominator, p.curve.params.p)
		denominator.ModInverse(denominator, p.curve.params.p)

		slope = new(big.Int).Mul(numerator, denominator)
		slope.Mod(slope, p.curve.params.p)
	} else {
		// Slope = (y2 - y1) / (x2 - x1)
		numerator := new(big.Int).Sub(q.y, p.y)
		numerator.Mod(numerator, p.curve.params.p)

		denominator := new(big.Int).Sub(q.x, p.x)
		denominator.Mod(denominator, p.curve.params.p)
		denominator.ModInverse(denominator, p.curve.params.p)

		slope = new(big.Int).Mul(numerator, denominator)
		slope.Mod(slope, p.curve.params.p)
	}

	// x = slope^2 - x2 - x1
	x := new(big.Int).Exp(slope, two, p.curve.params.p)
	x.Sub(x, p.x)
	x.Sub(x, q.x)
	x.Mod(x, p.curve.params.p)

	// y = slope*(x1 - x) - y1
	y := new(big.Int).Sub(p.x, x)
	y.Mul(y, slope)
	y.Sub(y, p.y)
	y.Mod(y, p.curve.params.p)

	result := &Point{x, y, p.curve}
	if checkPointsAfterEveryAdd {
		if !result.curve.IsOnCurve(result.x, result.y) {
			panic(fmt.Sprintf("Point is not on the curve (doubling = %v)", shouldDouble))
		}
	}
	return result
}

// Computes the additive inverse of a point
func (p *Point) Neg() *Point {
	if p.IsInfinity() {
		return p
	}
	return &Point{
		x:     new(big.Int).Set(p.x),
		y:     new(big.Int).Sub(p.curve.params.p, p.y),
		curve: p.curve,
	}
}

// Subtracts one point from another using the additive
// inverse
func (p *Point) Sub(q *Point) *Point {
	return p.Add(q.Neg())
}

// Scalar multiplication using double and add
func (p *Point) Mul(k *big.Int) *Point {
	if k.Sign() != 1 {
		panic("Invalid scalar")
	}

	if p.IsInfinity() {
		return p
	}

	result := p.curve.Infinity()
	accumulator := p
	bitlen := k.BitLen()
	for i := 0; i < bitlen; i++ {
		if k.Bit(i) == 1 {
			result = result.Add(accumulator)
		}
		accumulator = accumulator.Add(accumulator)
	}
	return result
}
