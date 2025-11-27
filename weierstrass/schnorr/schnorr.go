/*
Short Schnorr Signatures

Domain Parameters
------------------
p    - prime defining field
H(x) - TrucatedSha256(X) (bitlen(p)/2 bits)
G    - generator (Point)

User Parameters:
----------------
k    - signing secret key (scalar)
P    - signing public key (point)

Per Signature Parameters:
-------------------------
M    - message (bytes)
r    - ephemeral signing scalar (never transmitted, or re-used)
R    - ephemeral signing point corrisponding to r (recovered during verification)
R = G * r

Signature
-------------------------
e    - challenge (scalar) (bitlen(p)/2 bits)
s    - proof (scalar) (bitlen(p) bits)

--- Sign Phase ------
// Construct challenge and bind it to message, public key and ephemeral public key
e = H(R || P || M)

// Construct proof that signer knows k
s = r + ke

----Verify Phase-----
// Recover R (G * r) from s,e,P,G           Proof
R = (G * s) - (P * e)

	R = G * r                           // Definition of R
	R = G * (r + ke - ke)               // Add and subtract ke
	R = (G * (r + ke)) - (G * ke)       // Distribute G
	R = (G * (r + ke)) - ((G * k) * e)  // Extract e
	R = (G * s) - (P * e)               // Substitute s for (r + ke) and P for (G * k)

// Compute e' from R, P, M
e' = H(R || P || M)

Verify e = e'
*/
package schnorr

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/walterschell/customcurves/weierstrass"
	"github.com/walterschell/go-bitstream"
)

// Returns the size in bits of a serialized short signature
func ShortSignatureSize(c *weierstrass.Curve) int {
	return c.Params().P().BitLen() + c.Params().P().BitLen()/2
}

// Short Schnorr Signature
type ShortSignature struct {
	curve *weierstrass.Curve
	s     *big.Int
	e     *big.Int
}

func (s *ShortSignature) String() string {
	return fmt.Sprintf("[%s](s: 0x%x, e: 0x%x)", s.curve.Params().Name(), s.s, s.e)
}

// Verifies that the curve is the same and both scalars are the same
func (s *ShortSignature) Equals(other *ShortSignature) bool {
	return s == other || (s.curve.Equal(other.curve) &&
		s.e.Cmp(other.e) == 0 &&
		s.s.Cmp(other.s) == 0)
}

// Hash of s, e and curve
func (s *ShortSignature) Fingerprint() string {
	hash := sha256.New()
	hash.Write(s.s.Bytes())
	hash.Write(s.e.Bytes())
	hash.Write(s.curve.Params().SHA256Digest())
	return fmt.Sprintf("%x", hash.Sum(nil))
}

// Marshals to a bitstream
// s + e
func (s *ShortSignature) MarshalBitstream() *bitstream.BitStream {
	result := bitstream.BitStream{}
	result.AppendBigInt(s.s, uint(s.curve.Params().P().BitLen()))
	result.AppendBigInt(s.e, uint(s.curve.Params().P().BitLen())/2)
	return &result
}

// Unmarshals from bit stream
func UnmarshalShortSignature(c *weierstrass.Curve, bs *bitstream.BitStream) (*ShortSignature, error) {
	if bs.Size() != uint(ShortSignatureSize(c)) {
		return nil, fmt.Errorf("invalid bitstream size for short signature (expected %d, got %d)", ShortSignatureSize(c), bs.Size())
	}

	s := bs.BigIntAt(0, uint(c.Params().P().BitLen()))
	e := bs.BigIntAt(uint(c.Params().P().BitLen()), uint(c.Params().P().BitLen())/2)
	return &ShortSignature{curve: c, s: s, e: e}, nil
}

// Hashes data, and truncates to big int that fits into bitSize bits
func modSHA256(bitSize uint, msgChunks ...[]byte) *big.Int {
	hash := sha256.New()

	for _, chunk := range msgChunks {
		hash.Write(chunk)
	}
	sum := new(big.Int).SetBytes(hash.Sum(nil))
	m := new(big.Int).Lsh(big.NewInt(1), bitSize-1)
	sum.Mod(sum, m)
	return sum
}

// Secret key for using Schnorr signatures
type SecretKey weierstrass.Scalar

func (sk *SecretKey) Equals(other *SecretKey) bool {
	return sk == other || (*weierstrass.Scalar)(sk).Equals((*weierstrass.Scalar)(other))
}

func (sk *SecretKey) K() *big.Int {
	scalar := (*weierstrass.Scalar)(sk)
	return scalar.K()
}

func (sk *SecretKey) Curve() *weierstrass.Curve {
	scalar := (*weierstrass.Scalar)(sk)
	return scalar.Curve()
}

func (sk *SecretKey) PublicKey() *PublicKey {
	scalar := (*weierstrass.Scalar)(sk)
	point := scalar.Point()
	return (*PublicKey)(point)
}

func (sk *SecretKey) MarshalBinary() ([]byte, error) {
	return (*weierstrass.Scalar)(sk).MarshalBinary()
}

func UnmarshalSecretKey(c *weierstrass.Curve, data []byte) (*SecretKey, error) {
	scalar, err := c.UnmarshalScalar(data)
	if err != nil {
		return nil, err
	}
	return (*SecretKey)(scalar), nil
}

// Public key for using Schnorr signatures
type PublicKey weierstrass.Point

func (pk *PublicKey) Equals(other *PublicKey) bool {
	return pk == other || (*weierstrass.Point)(pk).Equals((*weierstrass.Point)(other))
}

func (pk *PublicKey) Curve() *weierstrass.Curve {
	point := (*weierstrass.Point)(pk)
	return point.Curve()
}
func (pk *PublicKey) X() *big.Int {
	point := (*weierstrass.Point)(pk)
	return point.X()
}
func (pk *PublicKey) Y() *big.Int {
	point := (*weierstrass.Point)(pk)
	return point.Y()
}

func (pk *PublicKey) MarshalBinary() ([]byte, error) {
	point := (*weierstrass.Point)(pk)
	return point.MarshalBinary()
}

// Unmarshals a public key
func UnmarshalPublicKey(c *weierstrass.Curve, data []byte) (*PublicKey, error) {
	point, err := c.UnmarshalPoint(data)
	if err != nil {
		return nil, err
	}
	return (*PublicKey)(point), nil
}

// Generates a new Schnorr keypair
func NewKeypair(curve *weierstrass.Curve) (*PublicKey, *SecretKey, error) {
	pub, sec, err := curve.NewKeypair()
	if err != nil {
		return nil, nil, err
	}
	return (*PublicKey)(pub), (*SecretKey)(sec), nil
}

/*
Computes Short Schnorr signature for msg
e = Hash(ephemeral public key + signing public key + msg)
s = ephemperal private key + (signing key * e)
*/
func (key *SecretKey) SignShort(msg []byte) (*ShortSignature, error) {

	R, r, err := key.Curve().NewKeypair()
	if err != nil {
		return nil, err
	}

	P := key.PublicKey()

	// e = H(R || P || M)
	e := modSHA256(uint(key.Curve().Params().BitSize())/2, R.X().Bytes(), R.Y().Bytes(), P.X().Bytes(), P.Y().Bytes(), msg)

	// s = r + ke
	ek := new(big.Int).Mul(e, key.K())
	ek = ek.Mod(ek, key.Curve().Params().N())

	s := new(big.Int).Add(r.K(), ek)
	s = s.Mod(s, key.Curve().Params().N())
	return &ShortSignature{
		curve: key.Curve(),
		s:     s,
		e:     e,
	}, nil
}

// Verifies a short Schnorr signature
func (p *PublicKey) VerifyShort(msg []byte, signature *ShortSignature) (bool, error) {

	P := (*weierstrass.Point)(p)
	if !p.Curve().Equal(signature.curve) {
		return false, fmt.Errorf("signature does not share same curve with public key")
	}

	// S = G * s
	S := p.Curve().G().Mul(signature.s)

	// R = S - (P*e)
	eP := P.Mul(signature.e)
	R := S.Sub(eP)

	// Recover e'
	e := modSHA256(uint(p.Curve().Params().BitSize())/2, R.X().Bytes(), R.Y().Bytes(), P.X().Bytes(), P.Y().Bytes(), msg)

	// Verify recovered e' matches signature e
	if signature.e.Cmp(e) != 0 {
		return false, fmt.Errorf("invalid e value")
	}
	return true, nil
}
