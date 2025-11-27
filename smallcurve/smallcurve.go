package smallcurve

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	bitstream "github.com/walterschell/go-bitstream"
)

// Represents a point on an elliptic curve
type Point struct {
	curve *CurveParameters
	x     uint64
	y     uint64
}


func (p *Point) String() string {
	return fmt.Sprintf("Point(%d, %d)", p.x, p.y)
}

// Verifies that coordinates are the same and that
// both points are on the same curve
func (p *Point) Equals(other *Point) bool {
	return p.x == other.x && p.y == other.y && p.curve == other.curve
}

// X coordinate of the point
func (p *Point) X() uint64 {
	return p.x
}


// Y coordinate of the point
func (p *Point) Y() uint64 {
	return p.y
}

func (p *Point) verify() bool {
	// y^2 = x^3 + ax + b
	if p.Equals(p.curve.infinity()) {
		return true
	}
	x3 := modexp(p.x, 3, p.curve.p)
	y2 := modexp(p.y, 2, p.curve.p)
	rhs := modsum(p.curve.p, x3, modmul(p.curve.a, p.x, p.curve.p), p.curve.b)
	lhs := y2
	return lhs == rhs
}

// Reflects a point about the X axis
func (p *Point) Negate() *Point {
	// Point at infinity
	if p.y == 0 {
		return &Point{curve: p.curve, x: p.x, y: p.y}
	}

	return &Point{curve: p.curve, x: p.x, y: p.curve.p - p.y}
}

// Adds two points geometrically
func (lhs *Point) Add(rhs *Point) *Point {

	pmul := func(x, y uint64) uint64 {
		return modmul(x, y, lhs.curve.p)
	}
	pexp := func(x, y uint64) uint64 {
		return modexp(x, y, lhs.curve.p)
	}
	psum := func(terms ...uint64) uint64 {

		return modsum(lhs.curve.p, terms...)
	}
	psub := func(x, y uint64) uint64 {
		return modsub(x, y, lhs.curve.p)
	}
	pinv := func(x uint64) uint64 {
		return modinvprime(x, lhs.curve.p)
	}
	if lhs.curve != rhs.curve {
		panic("Points are on different curves")
	}
	if !lhs.verify() {
		panic("lhs is not on the curve")
	}
	if !rhs.verify() {
		panic("rhs is not on the curve")
	}
	// If one of the points is the point at infinity, return the other point
	if lhs.y == 0 {
		if lhs.x != 0 {
			panic("lhs is unexpected")
		}
		return rhs
	}
	if rhs.y == 0 {
		if rhs.x != 0 {
			panic("rhs is unexpected")
		}
		return lhs
	}
	// If Both points have the same x value but different y values,
	// the result is the point at infinity
	if lhs.x == rhs.x && lhs.y != rhs.y {
		return &Point{curve: lhs.curve, x: 0, y: 0}
	}
	var slope uint64

	if lhs.x == rhs.x && lhs.y == rhs.y {
		numeratorTerms := []uint64{
			pmul(3, pexp(lhs.x, 2)),
			lhs.curve.a,
		}
		numerator := psum(numeratorTerms...)
		denominator := pmul(2, lhs.y)
		slope = pmul(numerator, pinv(denominator))
	} else {
		numerator := psub(rhs.y, lhs.y)
		denominator := psub(rhs.x, lhs.x)
		slope = pmul(numerator, pinv(denominator))
	}
	// x = s^2 - rhs.x - lhs.x
	x := psub(psub(pexp(slope, 2), rhs.x), lhs.x)

	// y = s(lhs.x - x) - lhs.y
	y := psub(pmul(slope, psub(lhs.x, x)), lhs.y)
	result := Point{curve: lhs.curve, x: x, y: y}
	if !result.verify() {
		panic("Result is not on the curve")
	}
	return &result
}

// Subtracts (Adding the inverse) one
// Point from another
func (p *Point) Sub(rhs *Point) *Point {
	return p.Add(rhs.Negate())
}

// Scalar point multiplication via double and add
func (p *Point) Multiply(scalar uint64) *Point {
	if scalar == 0 || scalar >= p.curve.p {
		panic(fmt.Sprintf("Invalid scalar %d", scalar))
	}
	sum := p.curve.infinity()
	d := p
	for scalar > 0 {
		if scalar&1 == 1 {
			sum = sum.Add(d)
		}
		d = d.Add(d)
		scalar >>= 1
	}
	return sum
}

// Marshal's a point to a bitstream
// X coordinate followed by sign bit
func (p *Point) MarshalBitstream() *bitstream.BitStream {
	result := bitstream.BitStream{}
	result.AppendUint(p.x, p.curve.bits)
	if p.y%2 == 1 {
		result.AppendBit(1)
	} else {
		result.AppendBit(0)
	}
	return &result
}

// Parameters for an elliptic curve that is small enough
// to use 64 bit math for
type CurveParameters struct {
	// The curve is defined by the equation y^2 = x^3 + ax + b over prime field F_p
	a     uint64
	b     uint64
	p     uint64
	bits  uint
	order uint64
	g_x   uint64
	g_y   uint64
}

// Fingerprint of curve parameters
// Used to sanity check serialized values relating
// to the curve
func (c *CurveParameters) Sha256Digest() []byte {
	hash := sha256.New()
	binary.Write(hash, binary.BigEndian, c.a)
	binary.Write(hash, binary.BigEndian, c.b)
	binary.Write(hash, binary.BigEndian, c.p)
	binary.Write(hash, binary.BigEndian, c.g_x)
	binary.Write(hash, binary.BigEndian, c.g_y)
	return hash.Sum(nil)
}

// Small (all values fit in 64 bits) elliptic curve

type Curve struct {
	parameters *CurveParameters
}

// Generator point for curve
func (c *Curve) G() *Point {
	return c.parameters.G()
}

// Unmarshals secret key (64 bit scalar)
// and verifies it looks sane for curve
func (c *Curve) UnmarshalSecretKeyBinary(data []byte) (*SecretKey, error) {
	if len(data) != 8 {
		return nil, fmt.Errorf("invalid secret key length %d", len(data))
	}
	key := binary.BigEndian.Uint64(data)
	if key >= c.parameters.order || key == 0 || key == 1 {
		return nil, fmt.Errorf("invalid key value %d", key)
	}
	return &SecretKey{
		key:   key,
		curve: c,
	}, nil
}

// Unmarshals a public key (point) for a curve and sanity checks it
func (c *Curve) UnmarshalPublicKeyBinary(data []byte) (*PublicKey, error) {
	if len(data) != 1+8+32 {
		return nil, fmt.Errorf("invalid public key length %d", len(data))
	}
	parity := data[0]
	if parity != 2 && parity != 3 {
		return nil, fmt.Errorf("invalid parity %d", parity)
	}
	x := binary.BigEndian.Uint64(data[1:9])
	if x >= c.parameters.p || x == 0 {
		return nil, fmt.Errorf("invalid x value %d", x)
	}

	// y^2 = x^3 + ax + b
	y := ModSqrt(
		modsum(c.parameters.p,
			modexp(x, 3, c.parameters.p),
			modmul(c.parameters.a, x, c.parameters.p),
			c.parameters.b,
		),
		c.parameters.p,
	)

	if y%2 != uint64(parity)%2 {
		y = c.parameters.p - y
	}

	curveHash := data[9:]
	expectedHash := c.parameters.Sha256Digest()
	if !bytes.Equal(curveHash, expectedHash) {
		return nil, fmt.Errorf("invalid curve hash")
	}

	return (*PublicKey)(&Point{curve: c.parameters, x: x, y: y}), nil
}


// Secret key using a given curve
type SecretKey struct {
	key   uint64
	curve *Curve
}

// Marshals the key
func (k *SecretKey) MarshalBinary() ([]byte, error) {
	result := make([]byte, 8)
	binary.BigEndian.PutUint64(result, k.key)
	return result, nil
}

// Public keys are points on a curve
type PublicKey Point

// Marshals the public key
// with fingerprint of curve for sanity checks
func (p *PublicKey) MarshalBinary() ([]byte, error) {
	result := bytes.Buffer{}
	if p.y%2 == 1 {
		result.WriteByte(3)
	} else {
		result.WriteByte(2)
	}
	binary.Write(&result, binary.BigEndian, p.x)
	result.Write(p.curve.Sha256Digest())
	return result.Bytes(), nil
}

// Generates a new keypair using r
func (c *Curve) NewKeypair() (publicKey *PublicKey, secretKey *SecretKey) {
	maxKey := c.parameters.order
	minKey := c.parameters.order / 2
	var key uint64
	for !(key >= minKey && key < maxKey) {
		keyBytes := [8]byte{}
		for {
			if _, err := rand.Read(keyBytes[:]); err == nil {
				break
			}
		}
		key = binary.BigEndian.Uint64(keyBytes[:])

	}
	publicPoint := c.parameters.G().Multiply(key)
	secretKey = &SecretKey{
		key:   key,
		curve: c,
	}
	publicKey = (*PublicKey)(publicPoint)
	return publicKey, secretKey
}

func (c *Curve) SignatureSize() uint {
	return (c.parameters.bits * 2) + 1
}

func (c *Curve) ShortSignatureSize() uint {
	return c.parameters.bits + (c.parameters.bits / 2)
}

func (k *SecretKey) PublicKey() *PublicKey {
	publicPoint := k.curve.parameters.G().Multiply(k.key)
	return (*PublicKey)(publicPoint)
}

type Signature struct {
	_R Point
	_s uint64
}

type ShortSignature struct {
	curve *CurveParameters
	e     uint64
	s     uint64
}

func (s *Signature) String() string {
	return fmt.Sprintf("Signature{R:%v, s:%d}", s._R.String(), s._s)
}

func (s *ShortSignature) String() string {
	return fmt.Sprintf("ShortSignature{e:%d, s:%d}", s.e, s.s)
}

func (s *Signature) Equals(other *Signature) bool {
	return s._R.Equals(&other._R) && s._s == other._s
}

func (s *ShortSignature) Equals(other *ShortSignature) bool {
	return s.curve == other.curve && s.e == other.e && s.s == other.s
}

func (s *Signature) Fingerprint() string {
	hash := sha256.New()
	u8 := make([]byte, 8)

	binary.BigEndian.PutUint64(u8, s._R.curve.a)
	hash.Write(u8)

	binary.BigEndian.PutUint64(u8, s._R.curve.b)
	hash.Write(u8)

	binary.BigEndian.PutUint64(u8, s._R.curve.p)
	hash.Write(u8)

	binary.BigEndian.PutUint64(u8, s._R.curve.g_x)
	hash.Write(u8)

	binary.BigEndian.PutUint64(u8, s._R.curve.g_y)
	hash.Write(u8)

	binary.BigEndian.PutUint64(u8, s._s)
	hash.Write(u8)

	binary.BigEndian.PutUint64(u8, s._R.x)
	hash.Write(u8)

	binary.BigEndian.PutUint64(u8, s._R.y)
	hash.Write(u8)
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func (s *ShortSignature) Fingerprint() string {
	hash := sha256.New()
	u8 := make([]byte, 8)

	binary.BigEndian.PutUint64(u8, s.curve.a)
	hash.Write(u8)

	binary.BigEndian.PutUint64(u8, s.curve.b)
	hash.Write(u8)

	binary.BigEndian.PutUint64(u8, s.curve.p)
	hash.Write(u8)

	binary.BigEndian.PutUint64(u8, s.curve.g_x)
	hash.Write(u8)

	binary.BigEndian.PutUint64(u8, s.curve.g_y)
	hash.Write(u8)

	binary.BigEndian.PutUint64(u8, s.s)
	hash.Write(u8)
	binary.BigEndian.PutUint64(u8, s.e)
	hash.Write(u8)
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func (s *Signature) MarshalBitstream() *bitstream.BitStream {
	result := bitstream.BitStream{}
	result.AppendBitstream(s._R.MarshalBitstream())
	result.AppendUint(s._s, s._R.curve.bits)
	return &result
}

func (s *ShortSignature) MarshalBitstream() *bitstream.BitStream {
	result := bitstream.BitStream{}
	result.AppendUint(s.s, s.curve.bits)
	result.AppendUint(s.e, s.curve.bits/2)
	return &result
}

func (c *Curve) UnmarshalSignature(bs *bitstream.BitStream) (*Signature, error) {
	expectedLength := c.parameters.bits*2 + 1
	if bs.Size() != expectedLength {
		return nil, fmt.Errorf("invalid signature length %d, expected %d", bs.Size(), expectedLength)
	}
	x := bs.UintAt(0, c.parameters.bits)
	parity := bs.BitAt(c.parameters.bits)
	s := bs.UintAt(c.parameters.bits+1, c.parameters.bits)

	R := c.parameters.Point(x, parity == 1)
	if !R.verify() || R == c.parameters.infinity() {
		return nil, fmt.Errorf("invalid R value")
	}
	if s >= c.parameters.order {
		return nil, fmt.Errorf("invalid s value greater than order")
	}
	return &Signature{
		_R: *R,
		_s: s,
	}, nil
}

func (c *Curve) UnmarshalShortSignature(bs *bitstream.BitStream) (*ShortSignature, error) {
	expectedLength := c.parameters.bits + c.parameters.bits/2
	if bs.Size() != expectedLength {
		return nil, fmt.Errorf("invalid signature length %d, expected %d", bs.Size(), expectedLength)
	}
	s := bs.UintAt(0, c.parameters.bits)
	e := bs.UintAt(c.parameters.bits, c.parameters.bits/2)
	return &ShortSignature{
		curve: c.parameters,
		e:     e,
		s:     s,
	}, nil
}

func modSHA256(m uint64, datas ...[]byte) uint64 {
	h := sha256.New()
	for _, data := range datas {
		h.Write(data)
	}
	fullhash := h.Sum(nil)
	n := binary.BigEndian.Uint64(fullhash[:8])
	return n % m
}

func (key *SecretKey) Sign(content []byte) *Signature {
	// s = k + ed

	d := key.key

	oadd := func(lhs, rhs uint64) uint64 {
		return modsum(key.curve.parameters.order, lhs, rhs)
	}
	omul := func(lhs, rhs uint64) uint64 {
		return modmul(lhs, rhs, key.curve.parameters.order)
	}

	R, k := key.curve.NewKeypair()
	RPoint := (*Point)(R)
	PPoint := (*Point)(key.PublicKey())

	// e = H(R || P || m)
	e := modSHA256(key.curve.parameters.order, RPoint.MarshalBitstream().ToBytes(), PPoint.MarshalBitstream().ToBytes(), content)

	// s = k + ed
	s := oadd(k.key, omul(e, d))

	return &Signature{
		_R: *RPoint,
		_s: s,
	}
}

func (key *SecretKey) SignShort(content []byte) *ShortSignature {
	// s = k + ed

	d := key.key

	oadd := func(lhs, rhs uint64) uint64 {
		return modsum(key.curve.parameters.order, lhs, rhs)
	}
	omul := func(lhs, rhs uint64) uint64 {
		return modmul(lhs, rhs, key.curve.parameters.order)
	}

	R, k := key.curve.NewKeypair()
	RPoint := (*Point)(R)
	PPoint := (*Point)(key.PublicKey())

	hashSizeBits := key.curve.parameters.bits / 2

	// e = H(R || P || m)
	e := modSHA256(1<<hashSizeBits, RPoint.MarshalBitstream().ToBytes(), PPoint.MarshalBitstream().ToBytes(), content)

	// s = k + ed
	s := oadd(k.key, omul(e, d))

	return &ShortSignature{
		curve: key.curve.parameters,
		e:     e,
		s:     s,
	}
}

func (p *PublicKey) Verify(content []byte, signature *Signature) (bool, error) {
	// s * G = R + e * P
	// (k + ed) * G = (k * G) + e * (d * G)
	// kG + edG = kG + edG
	if p.curve != signature._R.curve {
		return false, fmt.Errorf("Signature does not share same curve with public key")
	}
	e := modSHA256(p.curve.order, signature._R.MarshalBitstream().ToBytes(), (*Point)(p).MarshalBitstream().ToBytes(), content)
	lhs := p.curve.G().Multiply(signature._s)
	rhs := signature._R.Add((*Point)(p).Multiply(e))
	if !lhs.Equals(rhs) {
		return false, fmt.Errorf("Signature fails to validate")
	}
	return true, nil
}

func (p *PublicKey) VerifyShort(content []byte, signature *ShortSignature) (bool, error) {
	if p.curve.p != signature.curve.p {
		return false, fmt.Errorf("Signature does not share same curve with public key")
	}
	S := p.curve.G().Multiply(signature.s)
	eP := (*Point)(p).Multiply(signature.e)

	R := S.Sub(eP)
	e := modSHA256(1<<(signature.curve.bits/2), R.MarshalBitstream().ToBytes(), (*Point)(p).MarshalBitstream().ToBytes(), content)
	if e != signature.e {
		return false, fmt.Errorf("invalid e value")
	}
	return true, nil
}

func (c *CurveParameters) G() *Point {
	return &Point{curve: c, x: c.g_x, y: c.g_y}
}

func (c *CurveParameters) Point(x uint64, odd bool) *Point {
	x3 := modexp(x, 3, c.p)
	y2 := modsum(c.p, x3, modmul(c.a, x, c.p), c.b)
	y := ModSqrt(y2, c.p)
	if y%2 == 0 && odd {
		y = c.p - y
	} else if y%2 == 1 && !odd {
		y = c.p - y
	}
	return &Point{curve: c, x: x, y: y}
}

func (c *CurveParameters) infinity() *Point {
	return &Point{curve: c, x: 0, y: 0}
}

var C50Parameters CurveParameters = CurveParameters{
	a:     0x00ed67ad940562,
	b:     0x00eb5057ec865a,
	p:     0x0388cde6d6a9eb,
	bits:  50,
	order: 0x0388cde32d4ae9,
	g_x:   0x01f06020c60e80,
	g_y:   0x037a7e95e6abf6,
}

var C50 Curve = Curve{parameters: &C50Parameters}

var tinyParameters CurveParameters = CurveParameters{
	a:     63,
	b:     33,
	p:     103,
	bits:  7,
	order: 97,
	g_x:   90,
	g_y:   2,
}

var C64Parameters CurveParameters = CurveParameters{
	a:     0x197eacf564277a28,
	b:     0x2869c4a069451233,
	p:     0xfc477ce0dee80f77,
	bits:  64,
	order: 0xfc477ce09e86adfb,
	g_x:   0x56853b2bd6052661,
	g_y:   0xcb116939be0710c9,
}
var C64 Curve = Curve{parameters: &C64Parameters}
