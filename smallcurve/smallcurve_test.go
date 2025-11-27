package smallcurve

import (
	"testing"
)

func TestBigNumber(t *testing.T) {
	final := C50Parameters.p - 1

	a := final / 2
	b := final - a

	A := C50Parameters.G().Multiply(a)
	B := C50Parameters.G().Multiply(b)
	Final := C50Parameters.G().Multiply(final)

	// Test addition
	D := A.Add(B)
	if !D.Equals(Final) {
		t.Errorf("Addition failed: %v + %v = %v, expected %v", A, B, D, Final)
	}

	c := modmul(a, b, C50Parameters.order)
	C := C50Parameters.G().Multiply(c)
	// c = a * b
	// C = c * G
	// C == b * A
	// (a *b) * G == b * (a * G)

	if !A.Multiply(b).Equals(C) {
		t.Errorf("Multiplication failed: %v * %v = %v, expected %v", A, b, A.Multiply(b), C)
	}

}

func TestSigning(t *testing.T) {
	// Test signing and verifying a message
	message := ([]byte)("Hello, world!")
	publicKey, secretKey := C50.NewKeypair()
	signature := secretKey.Sign(message)
	ok, err := publicKey.Verify(message, signature)
	if !ok {
		t.Errorf("Failed to verify signature: %v", err)
	}
	t.Logf("Signature: %v\n", signature)
	serialized := signature.MarshalBitstream()

	// Test deserialization
	deserialized, err := C50.UnmarshalSignature(serialized)
	if err != nil {
		t.Fatalf("Failed to deserialize signature: %v", err)
	}
	if !deserialized.Equals(signature) {
		t.Fatalf("Deserialized signature does not match original: (actual) %v != (expected) %v", deserialized, signature)
	}
	ok, err = publicKey.Verify(message, deserialized)
	if !ok {
		t.Errorf("Failed to verify deserialized signature: %v", err)
	}
}

func TestShortSigning(t *testing.T) {
	// Test signing and verifying a message
	message := ([]byte)("Hello, world!")
	publicKey, secretKey := C50.NewKeypair()
	signature := secretKey.SignShort(message)
	ok, err := publicKey.VerifyShort(message, signature)
	if !ok {
		t.Fatalf("Failed to verify signature: %v", err)
	}
	t.Logf("Signature: %v\n", signature)
	serialized := signature.MarshalBitstream()

	// Test deserialization
	deserialized, err := C50.UnmarshalShortSignature(serialized)
	if err != nil {
		t.Fatalf("Failed to deserialize signature: %v", err)
	}
	if !deserialized.Equals(signature) {
		t.Fatalf("Deserialized signature does not match original: (actual) %v != (expected) %v", deserialized, signature)
	}
	ok, err = publicKey.VerifyShort(message, deserialized)
	if !ok {
		t.Errorf("Failed to verify deserialized signature: %v", err)
	}
}

func TestC64(t *testing.T) {
	message := ([]byte)("Hello, world!")
	publicKey, secretKey := C64.NewKeypair()

	for i := 0; i < 100; i++ {
		signature := secretKey.SignShort(message)
		if signature.MarshalBitstream().Size() != 96 {
			t.Fatalf("Signature is not 96 bytes long: %v", signature.MarshalBitstream().Size())
		}
		ok, err := publicKey.VerifyShort(message, signature)
		if !ok {
			t.Fatalf("Failed to verify signature: %v", err)
		}
		serialized := signature.MarshalBitstream()

		deserialized, err := C64.UnmarshalShortSignature(serialized)
		if err != nil {
			t.Fatalf("Failed to deserialize signature: %v", err)
		}
		if !deserialized.Equals(signature) {
			t.Fatalf("Deserialized signature does not match original: (actual) %v != (expected) %v", deserialized, signature)
		}
		ok, err = publicKey.VerifyShort(message, deserialized)
		if !ok {
			t.Errorf("Failed to verify deserialized signature: %v", err)
		}
	}
}

func testDoubling(t *testing.T, curve *Curve) {
	// Test doubling
	A := curve.G().Multiply(2)
	B := curve.G().Multiply(1)
	C := B.Add(B)
	if !C.Equals(A) {
		t.Errorf("Doubling failed: %v + %v = %v, expected %v", B, B, C, A)
	}
}

func TestDoubleTiny(t *testing.T) {
	cTiny := Curve{
		parameters: &tinyParameters,
	}
	testDoubling(t, &cTiny)
}
