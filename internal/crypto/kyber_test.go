package crypto

import "testing"

func TestKyberEncapsulateDecapsulateRoundTrip(t *testing.T) {
	pub, priv, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("GenerateKyberKeyPair: %v", err)
	}

	ct, shared1, err := EncapsulateKyber(pub)
	if err != nil {
		t.Fatalf("EncapsulateKyber: %v", err)
	}

	shared2, err := DecapsulateKyber(priv, ct)
	if err != nil {
		t.Fatalf("DecapsulateKyber: %v", err)
	}

	if string(shared1) != string(shared2) {
		t.Fatal("kyber shared secrets do not match")
	}
}

func TestKyberRejectsInvalidPublicKeySize(t *testing.T) {
	if _, _, err := EncapsulateKyber([]byte("bad")); err == nil {
		t.Fatal("expected invalid public key size error")
	}
}

func TestKyberRejectsInvalidPrivateKeySize(t *testing.T) {
	if _, err := DecapsulateKyber([]byte("bad"), []byte("ciphertext")); err == nil {
		t.Fatal("expected invalid private key size error")
	}
}

func TestKyberRejectsInvalidCiphertextSize(t *testing.T) {
	_, priv, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("GenerateKyberKeyPair: %v", err)
	}

	if _, err := DecapsulateKyber(priv, []byte("bad")); err == nil {
		t.Fatal("expected invalid ciphertext size error")
	}
}
