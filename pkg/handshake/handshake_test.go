package handshake

import (
	"bytes"
	"strings"
	"testing"

	"github.com/cloudflare/circl/dh/x448"
	"github.com/cloudflare/circl/sign/ed448"
	intcrypto "github.com/slipe-fun/skid/internal/crypto"
	"github.com/slipe-fun/skid/pkg/identity"
	"github.com/slipe-fun/skid/pkg/protocol"
)

func newSignedBundle(t *testing.T) (*identity.PublicPreKeyBundle, *identity.PrivatePreKeyBundle) {
	t.Helper()

	publicDevice, privateDevice, err := identity.NewDevice()
	if err != nil {
		t.Fatalf("NewDevice: %v", err)
	}

	publicBundle, privateBundle, err := identity.NewPreKeyBundle(publicDevice, privateDevice)
	if err != nil {
		t.Fatalf("NewPreKeyBundle: %v", err)
	}

	return publicBundle, privateBundle
}

func TestInitiateRespondDeriveSameSharedKey(t *testing.T) {
	bobPublicBundle, bobPrivateBundle := newSignedBundle(t)
	alicePublicBundle, alicePrivateBundle := newSignedBundle(t)

	aliceEKPub, aliceEKPriv, err := intcrypto.GenerateECDHKeyPair()
	if err != nil {
		t.Fatalf("GenerateECDHKeyPair: %v", err)
	}

	aliceShared, preKeyMessage, err := Initiate(alicePublicBundle.IK_Pub, alicePrivateBundle.IK_Priv, aliceEKPub, aliceEKPriv, bobPublicBundle)
	if err != nil {
		t.Fatalf("Initiate: %v", err)
	}

	bobShared, err := Respond(bobPrivateBundle, preKeyMessage)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}

	if !bytes.Equal(aliceShared, bobShared) {
		t.Fatal("initiator and responder shared keys differ")
	}

	if preKeyMessage.Version != protocol.CurrentVersion || preKeyMessage.Type != protocol.MessageTypePreKey {
		t.Fatal("unexpected prekey message metadata")
	}

	if !bytes.Equal(preKeyMessage.IKPub, alicePublicBundle.IK_Pub[:]) {
		t.Fatal("prekey message IK does not match initiator IK")
	}
	if !bytes.Equal(preKeyMessage.EKPub, aliceEKPub[:]) {
		t.Fatal("prekey message EK does not match initiator EK")
	}
}

func TestInitiateRejectsInvalidBundleSignature(t *testing.T) {
	bobPublicBundle, _ := newSignedBundle(t)
	alicePublicBundle, alicePrivateBundle := newSignedBundle(t)

	aliceEKPub, aliceEKPriv, err := intcrypto.GenerateECDHKeyPair()
	if err != nil {
		t.Fatalf("GenerateECDHKeyPair: %v", err)
	}

	tampered := *bobPublicBundle
	tampered.Kyber768_Pub = append([]byte(nil), bobPublicBundle.Kyber768_Pub...)
	tampered.Kyber768_Pub[0] ^= 0xFF

	if _, _, err := Initiate(alicePublicBundle.IK_Pub, alicePrivateBundle.IK_Priv, aliceEKPub, aliceEKPriv, &tampered); err == nil || !strings.Contains(err.Error(), "invalid signature") {
		t.Fatalf("expected invalid signature error, got %v", err)
	}
}

func TestInitiateRejectsLowOrderBundleKey(t *testing.T) {
	publicDevice, privateDevice, err := identity.NewDevice()
	if err != nil {
		t.Fatalf("NewDevice: %v", err)
	}

	ikPub, _, err := intcrypto.GenerateECDHKeyPair()
	if err != nil {
		t.Fatalf("GenerateECDHKeyPair(IK): %v", err)
	}
	opkPub, _, err := intcrypto.GenerateECDHKeyPair()
	if err != nil {
		t.Fatalf("GenerateECDHKeyPair(OPK): %v", err)
	}
	kyberPub, _, err := intcrypto.GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("GenerateKyberKeyPair: %v", err)
	}

	maliciousBundle := &identity.PublicPreKeyBundle{
		IK_Pub:        ikPub,
		SPK_Pub:       x448.Key{},
		OPK_Pub:       opkPub,
		Kyber768_Pub:  kyberPub,
		Signature_Pub: publicDevice.SignatureKey,
	}
	maliciousBundle.Signature = ed448.Sign(privateDevice.SignatureKey, identity.BuildPrekeyBundleHash(maliciousBundle), identity.PrekeyBundleDomainPrefix)

	alicePublicBundle, alicePrivateBundle := newSignedBundle(t)
	aliceEKPub, aliceEKPriv, err := intcrypto.GenerateECDHKeyPair()
	if err != nil {
		t.Fatalf("GenerateECDHKeyPair: %v", err)
	}

	if _, _, err := Initiate(alicePublicBundle.IK_Pub, alicePrivateBundle.IK_Priv, aliceEKPub, aliceEKPriv, maliciousBundle); err == nil || !strings.Contains(err.Error(), "low-order") {
		t.Fatalf("expected low-order point error, got %v", err)
	}
}

func TestRespondRejectsNilPreKeyMessage(t *testing.T) {
	_, bobPrivateBundle := newSignedBundle(t)

	if _, err := Respond(bobPrivateBundle, nil); err == nil {
		t.Fatal("expected nil prekey message error")
	}
}

func TestRespondRejectsUnsupportedVersion(t *testing.T) {
	_, bobPrivateBundle := newSignedBundle(t)

	msg := &protocol.PreKeyMessage{
		Version: protocol.CurrentVersion + 1,
		Type:    protocol.MessageTypePreKey,
	}

	if _, err := Respond(bobPrivateBundle, msg); err == nil || !strings.Contains(err.Error(), "unsupported prekey message version") {
		t.Fatalf("expected unsupported version error, got %v", err)
	}
}

func TestRespondRejectsUnexpectedType(t *testing.T) {
	_, bobPrivateBundle := newSignedBundle(t)

	msg := &protocol.PreKeyMessage{
		Version: protocol.CurrentVersion,
		Type:    protocol.MessageTypeRatchet,
	}

	if _, err := Respond(bobPrivateBundle, msg); err == nil || !strings.Contains(err.Error(), "unexpected prekey message type") {
		t.Fatalf("expected unexpected type error, got %v", err)
	}
}

func TestRespondRejectsInvalidKeyLength(t *testing.T) {
	_, bobPrivateBundle := newSignedBundle(t)

	msg := &protocol.PreKeyMessage{
		Version: protocol.CurrentVersion,
		Type:    protocol.MessageTypePreKey,
		IKPub:   []byte{1, 2, 3},
		EKPub:   make([]byte, len(x448.Key{})),
	}

	if _, err := Respond(bobPrivateBundle, msg); err == nil || !strings.Contains(err.Error(), "invalid x448 key length") {
		t.Fatalf("expected invalid x448 key length error, got %v", err)
	}
}

func TestRespondRejectsInvalidKyberCiphertextSize(t *testing.T) {
	bobPublicBundle, bobPrivateBundle := newSignedBundle(t)
	alicePublicBundle, alicePrivateBundle := newSignedBundle(t)

	aliceEKPub, aliceEKPriv, err := intcrypto.GenerateECDHKeyPair()
	if err != nil {
		t.Fatalf("GenerateECDHKeyPair: %v", err)
	}

	_, msg, err := Initiate(alicePublicBundle.IK_Pub, alicePrivateBundle.IK_Priv, aliceEKPub, aliceEKPriv, bobPublicBundle)
	if err != nil {
		t.Fatalf("Initiate: %v", err)
	}

	msg.KyberCiphertext = []byte("bad")

	if _, err := Respond(bobPrivateBundle, msg); err == nil || !strings.Contains(err.Error(), "invalid ciphertext size") {
		t.Fatalf("expected invalid ciphertext size error, got %v", err)
	}
}
