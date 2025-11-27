package schnorr

import (
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/walterschell/customcurves/weierstrass"
)

// P256 Curve Parameters in JSON format
// Note that a is -3 mod p
const p256json = `
{
	"p": "0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
	"a": "0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
	"b": "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
	"gx": "0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
	"gy": "0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
	"n": "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
	"name": "p256"
}
`

func P256Params() *weierstrass.CurveParams {
	curvemap := make(map[string]string)
	err := json.Unmarshal([]byte(p256json), &curvemap)
	if err != nil {
		panic(fmt.Sprintf("p256: invalid json >> %v", err))
	}

	p, ok := new(big.Int).SetString(curvemap["p"], 0)
	if !ok {
		panic(fmt.Sprintf("p256: invalid p >> %v", curvemap["p"]))
	}
	a, ok := new(big.Int).SetString(curvemap["a"], 0)
	if !ok {
		panic(fmt.Sprintf("p256: invalid a >> %v", curvemap["a"]))
	}
	b, ok := new(big.Int).SetString(curvemap["b"], 0)
	if !ok {
		panic(fmt.Sprintf("p256: invalid b >> %v", curvemap["b"]))
	}
	gx, ok := new(big.Int).SetString(curvemap["gx"], 0)
	if !ok {
		panic(fmt.Sprintf("p256: invalid gx >> %v", curvemap["gx"]))
	}
	gy, ok := new(big.Int).SetString(curvemap["gy"], 0)
	if !ok {
		panic(fmt.Sprintf("p256: invalid gy >> %v", curvemap["gy"]))
	}
	n, ok := new(big.Int).SetString(curvemap["n"], 0)
	if !ok {
		panic(fmt.Sprintf("p256: invalid n >> %v", curvemap["n"]))
	}
	result, err := weierstrass.NewCurveParamsFromBigInts(p, a, b, gx, gy, n, curvemap["name"])
	if err != nil {
		panic(fmt.Sprintf("p256: invalid curve params >> %v", err))
	}
	return result
}

func P256Curve() *weierstrass.Curve {
	return weierstrass.NewCurve(P256Params())
}

func TestSigning(t *testing.T) {
	message := []byte("This is an awesome message")
	curve := P256Curve()

	pkey, skey, err := NewKeypair(curve)
	if err != nil {
		t.Fatalf("Could not generate keypair")
	}

	signature, err := skey.SignShort(message)
	if err != nil {
		t.Fatalf("Could not sign: %v", err)
	}

	valid, err := pkey.VerifyShort(message, signature)
	if !valid {
		t.Fatalf("Signature did not verify: %v", err)
	}
	t.Logf("Signature verified correctly")

}

func TestSigningWithSerialization(t *testing.T) {
	message := []byte("This is an awesome message")
	curve := P256Curve()

	pkey, skey, err := NewKeypair(curve)
	if err != nil {
		t.Fatalf("Could not generate keypair")
	}

	signature, err := skey.SignShort(message)
	if err != nil {
		t.Fatalf("Could not sign: %v", err)
	}

	serialized := signature.MarshalBitstream()

	deserialized, err := UnmarshalShortSignature(curve, serialized)
	if err != nil {
		t.Fatalf("Could not deserialize signature: %v", err)
	}
	t.Logf("Original: %v\n", signature)
	t.Logf("Deserialized: %v\n", deserialized)
	if !signature.Equals(deserialized) {
		t.Fatalf("Deserialized signature does not match original")
	}

	valid, err := pkey.VerifyShort(message, deserialized)
	if !valid {
		t.Fatalf("Signature did not verify: %v", err)
	}
	t.Logf("Signature verified correctly")

}

func TestEndToEndSigning(t *testing.T) {
	message := []byte("This is an awesome message")
	curve := P256Curve()

	pkey, skey, err := curve.NewKeypair()
	if err != nil {
		t.Fatalf("Could not generate keypair")
	}

	serializedSkey, err := skey.MarshalBinary()
	if err != nil {
		t.Fatalf("Could not serialize secret key")
	}
	serializedPkey, err := pkey.MarshalBinary()
	if err != nil {
		t.Fatalf("Could not serialize public key")
	}

	deserializedSkey, err := UnmarshalSecretKey(curve, serializedSkey)
	if err != nil {
		t.Fatalf("Could not deserialize secret key")
	}
	deserializedPkey, err := UnmarshalPublicKey(curve, serializedPkey)
	if err != nil {
		t.Fatalf("Could not deserialize public key")
	}
	signature, err := deserializedSkey.SignShort(message)
	if err != nil {
		t.Fatalf("Could not sign: %v", err)
	}
	serializedSignature := signature.MarshalBitstream()

	deserializedSignature, err := UnmarshalShortSignature(curve, serializedSignature)
	if err != nil {
		t.Fatalf("Could not deserialize signature")
	}
	valid, err := deserializedPkey.VerifyShort(message, deserializedSignature)
	if !valid {
		t.Fatalf("Signature did not verify: %v", err)
	}
	t.Logf("Signature verified correctly")
}
