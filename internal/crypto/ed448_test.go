package crypto

import (
	"testing"

	"github.com/cloudflare/circl/sign/ed448"
)

func TestGenerateEd448KeyPairSignVerify(t *testing.T) {
	pub, priv, err := GenerateEd448KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd448KeyPair: %v", err)
	}

	msg := []byte("signed bundle")
	sig := ed448.Sign(ed448.PrivateKey(priv), msg, "SKID-BUNDLE-V1")

	if !ed448.Verify(ed448.PublicKey(pub), msg, sig, "SKID-BUNDLE-V1") {
		t.Fatal("signature verification failed")
	}

	if ed448.Verify(ed448.PublicKey(pub), msg, sig, "WRONG-CONTEXT") {
		t.Fatal("signature verification should fail with wrong context")
	}
}
