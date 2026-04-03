package crypto

import (
	"bytes"
	"testing"

	"github.com/cloudflare/circl/dh/x448"
)

func TestGenerateECDHKeyPairSharedSecretMatches(t *testing.T) {
	alicePub, alicePriv, err := GenerateECDHKeyPair()
	if err != nil {
		t.Fatalf("GenerateECDHKeyPair(alice): %v", err)
	}

	bobPub, bobPriv, err := GenerateECDHKeyPair()
	if err != nil {
		t.Fatalf("GenerateECDHKeyPair(bob): %v", err)
	}

	var aliceShared, bobShared x448.Key
	if !x448.Shared(&aliceShared, &alicePriv, &bobPub) {
		t.Fatal("alice shared secret derivation failed")
	}
	if !x448.Shared(&bobShared, &bobPriv, &alicePub) {
		t.Fatal("bob shared secret derivation failed")
	}

	if !bytes.Equal(aliceShared[:], bobShared[:]) {
		t.Fatalf("shared secret mismatch: %x != %x", aliceShared, bobShared)
	}
}

func TestX3DHInitiatorResponderMatch(t *testing.T) {
	ikaPub, ikaPriv, err := GenerateECDHKeyPair()
	if err != nil {
		t.Fatalf("GenerateECDHKeyPair(IKA): %v", err)
	}
	ekaPub, ekaPriv, err := GenerateECDHKeyPair()
	if err != nil {
		t.Fatalf("GenerateECDHKeyPair(EKA): %v", err)
	}
	ikbPub, ikbPriv, err := GenerateECDHKeyPair()
	if err != nil {
		t.Fatalf("GenerateECDHKeyPair(IKB): %v", err)
	}
	spkbPub, spkbPriv, err := GenerateECDHKeyPair()
	if err != nil {
		t.Fatalf("GenerateECDHKeyPair(SPKB): %v", err)
	}
	opkbPub, opkbPriv, err := GenerateECDHKeyPair()
	if err != nil {
		t.Fatalf("GenerateECDHKeyPair(OPKB): %v", err)
	}

	a1, a2, a3, a4, err := X3DH_Initiator(ikaPriv, ekaPriv, ikbPub, spkbPub, opkbPub)
	if err != nil {
		t.Fatalf("X3DH_Initiator: %v", err)
	}

	b1, b2, b3, b4, err := X3DH_Responder(ikbPriv, spkbPriv, opkbPriv, ikaPub, ekaPub)
	if err != nil {
		t.Fatalf("X3DH_Responder: %v", err)
	}

	if !bytes.Equal(a1[:], b1[:]) || !bytes.Equal(a2[:], b2[:]) || !bytes.Equal(a3[:], b3[:]) || !bytes.Equal(a4[:], b4[:]) {
		t.Fatal("initiator and responder X3DH outputs differ")
	}
}

func TestX3DHInitiatorRejectsLowOrderPoint(t *testing.T) {
	ikaPub, ikaPriv, err := GenerateECDHKeyPair()
	if err != nil {
		t.Fatalf("GenerateECDHKeyPair(IKA): %v", err)
	}
	_ = ikaPub

	ekaPub, ekaPriv, err := GenerateECDHKeyPair()
	if err != nil {
		t.Fatalf("GenerateECDHKeyPair(EKA): %v", err)
	}
	_ = ekaPub

	ikbPub, _, err := GenerateECDHKeyPair()
	if err != nil {
		t.Fatalf("GenerateECDHKeyPair(IKB): %v", err)
	}
	opkbPub, _, err := GenerateECDHKeyPair()
	if err != nil {
		t.Fatalf("GenerateECDHKeyPair(OPKB): %v", err)
	}

	if _, _, _, _, err := X3DH_Initiator(ikaPriv, ekaPriv, ikbPub, x448.Key{}, opkbPub); err == nil {
		t.Fatal("expected low-order point rejection for initiator")
	}
}

func TestX3DHResponderRejectsLowOrderPoint(t *testing.T) {
	ikbPub, ikbPriv, err := GenerateECDHKeyPair()
	if err != nil {
		t.Fatalf("GenerateECDHKeyPair(IKB): %v", err)
	}
	_ = ikbPub

	spkbPub, spkbPriv, err := GenerateECDHKeyPair()
	if err != nil {
		t.Fatalf("GenerateECDHKeyPair(SPKB): %v", err)
	}
	_ = spkbPub

	opkbPub, opkbPriv, err := GenerateECDHKeyPair()
	if err != nil {
		t.Fatalf("GenerateECDHKeyPair(OPKB): %v", err)
	}
	_ = opkbPub

	ekaPub, _, err := GenerateECDHKeyPair()
	if err != nil {
		t.Fatalf("GenerateECDHKeyPair(EKA): %v", err)
	}

	if _, _, _, _, err := X3DH_Responder(ikbPriv, spkbPriv, opkbPriv, x448.Key{}, ekaPub); err == nil {
		t.Fatal("expected low-order point rejection for responder")
	}
}
