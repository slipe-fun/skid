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

type handshakeFixture struct {
	bobPublicDevice  *identity.PublicDevice
	bobPrivateDevice *identity.PrivateDevice
	bobPublicBundle  *identity.PublicPreKeyBundle
	bobPrivateBundle *identity.PrivatePreKeyBundle

	alicePublicDevice  *identity.PublicDevice
	alicePrivateDevice *identity.PrivateDevice

	aliceShared []byte
	preKeyMsg   *protocol.PreKeyMessage
}

func newSignedBundle(t *testing.T) (*identity.PublicDevice, *identity.PrivateDevice, *identity.PublicPreKeyBundle, *identity.PrivatePreKeyBundle) {
	t.Helper()

	publicDevice, privateDevice, err := identity.NewDevice()
	if err != nil {
		t.Fatalf("NewDevice: %v", err)
	}

	publicBundle, privateBundle, err := identity.NewPreKeyBundle(publicDevice, privateDevice)
	if err != nil {
		t.Fatalf("NewPreKeyBundle: %v", err)
	}

	return publicDevice, privateDevice, publicBundle, privateBundle
}

func newHandshakeFixture(t *testing.T) *handshakeFixture {
	t.Helper()

	bobPublicDevice, bobPrivateDevice, bobPublicBundle, bobPrivateBundle := newSignedBundle(t)

	alicePublicDevice, alicePrivateDevice, err := identity.NewDevice()
	if err != nil {
		t.Fatalf("NewDevice(alice): %v", err)
	}

	aliceEKPub, aliceEKPriv, err := intcrypto.GenerateECDHKeyPair()
	if err != nil {
		t.Fatalf("GenerateECDHKeyPair(EK): %v", err)
	}

	aliceShared, preKeyMsg, err := Initiate(aliceEKPub, aliceEKPriv, alicePublicDevice, alicePrivateDevice, bobPublicDevice, bobPublicBundle)
	if err != nil {
		t.Fatalf("Initiate: %v", err)
	}

	aliceDR, err := protocol.NewSessionInitiator(aliceShared, bobPublicBundle.SPK_Pub)
	if err != nil {
		t.Fatalf("NewSessionInitiator: %v", err)
	}

	preKeyMsg.Message, err = aliceDR.Encrypt([]byte("embedded first message"), alicePublicDevice.IK[:], bobPublicDevice.IK[:])
	if err != nil {
		t.Fatalf("Encrypt(first message): %v", err)
	}

	return &handshakeFixture{
		bobPublicDevice:    bobPublicDevice,
		bobPrivateDevice:   bobPrivateDevice,
		bobPublicBundle:    bobPublicBundle,
		bobPrivateBundle:   bobPrivateBundle,
		alicePublicDevice:  alicePublicDevice,
		alicePrivateDevice: alicePrivateDevice,
		aliceShared:        aliceShared,
		preKeyMsg:          preKeyMsg,
	}
}

func TestInitiateRespondDeriveSameSharedKey(t *testing.T) {
	fixture := newHandshakeFixture(t)

	bobShared, err := Respond(fixture.bobPrivateDevice, fixture.bobPrivateBundle, fixture.alicePublicDevice, fixture.preKeyMsg)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}

	if !bytes.Equal(fixture.aliceShared, bobShared) {
		t.Fatal("initiator and responder shared keys differ")
	}

	if fixture.preKeyMsg.Version != protocol.CurrentVersion || fixture.preKeyMsg.Type != protocol.MessageTypePreKey {
		t.Fatal("unexpected prekey message metadata")
	}

	if !bytes.Equal(fixture.preKeyMsg.IKPub, fixture.alicePublicDevice.IK[:]) {
		t.Fatal("prekey message IK does not match initiator IK")
	}
	if fixture.preKeyMsg.Message == nil {
		t.Fatal("expected nested ratchet message to be present")
	}
}

func TestInitiateRejectsInvalidBundleSignature(t *testing.T) {
	bobPublicDevice, _, bobPublicBundle, _ := newSignedBundle(t)
	alicePublicDevice, alicePrivateDevice, err := identity.NewDevice()
	if err != nil {
		t.Fatalf("NewDevice(alice): %v", err)
	}

	aliceEKPub, aliceEKPriv, err := intcrypto.GenerateECDHKeyPair()
	if err != nil {
		t.Fatalf("GenerateECDHKeyPair: %v", err)
	}

	tampered := *bobPublicBundle
	tampered.Kyber768_Pub = append([]byte(nil), bobPublicBundle.Kyber768_Pub...)
	tampered.Kyber768_Pub[0] ^= 0xFF

	if _, _, err := Initiate(aliceEKPub, aliceEKPriv, alicePublicDevice, alicePrivateDevice, bobPublicDevice, &tampered); err == nil || !strings.Contains(err.Error(), "invalid signature") {
		t.Fatalf("expected invalid signature error, got %v", err)
	}
}

func TestInitiateRejectsLowOrderBundleKey(t *testing.T) {
	bobPublicDevice, bobPrivateDevice, err := identity.NewDevice()
	if err != nil {
		t.Fatalf("NewDevice(bob): %v", err)
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
		SPK_Pub:       x448.Key{},
		OPK_Pub:       opkPub,
		Kyber768_Pub:  kyberPub,
		Signature_Pub: bobPublicDevice.SignatureKey,
	}
	maliciousBundle.Signature = ed448.Sign(
		bobPrivateDevice.SignatureKey,
		identity.BuildPrekeyBundleHash(maliciousBundle),
		identity.PrekeyBundleDomainPrefix,
	)

	alicePublicDevice, alicePrivateDevice, err := identity.NewDevice()
	if err != nil {
		t.Fatalf("NewDevice(alice): %v", err)
	}
	aliceEKPub, aliceEKPriv, err := intcrypto.GenerateECDHKeyPair()
	if err != nil {
		t.Fatalf("GenerateECDHKeyPair(EK): %v", err)
	}

	if _, _, err := Initiate(aliceEKPub, aliceEKPriv, alicePublicDevice, alicePrivateDevice, bobPublicDevice, maliciousBundle); err == nil || !strings.Contains(err.Error(), "low-order") {
		t.Fatalf("expected low-order point error, got %v", err)
	}
}

func TestRespondRejectsNilPreKeyMessage(t *testing.T) {
	_, bobPrivateDevice, _, bobPrivateBundle := newSignedBundle(t)
	alicePublicDevice, _, err := identity.NewDevice()
	if err != nil {
		t.Fatalf("NewDevice(alice): %v", err)
	}

	if _, err := Respond(bobPrivateDevice, bobPrivateBundle, alicePublicDevice, nil); err == nil {
		t.Fatal("expected nil prekey message error")
	}
}

func TestRespondRejectsUnsupportedVersion(t *testing.T) {
	_, bobPrivateDevice, _, bobPrivateBundle := newSignedBundle(t)
	alicePublicDevice, _, err := identity.NewDevice()
	if err != nil {
		t.Fatalf("NewDevice(alice): %v", err)
	}

	msg := &protocol.PreKeyMessage{
		Version: protocol.CurrentVersion + 1,
		Type:    protocol.MessageTypePreKey,
	}

	if _, err := Respond(bobPrivateDevice, bobPrivateBundle, alicePublicDevice, msg); err == nil || !strings.Contains(err.Error(), "unsupported prekey message version") {
		t.Fatalf("expected unsupported version error, got %v", err)
	}
}

func TestRespondRejectsUnexpectedType(t *testing.T) {
	_, bobPrivateDevice, _, bobPrivateBundle := newSignedBundle(t)
	alicePublicDevice, _, err := identity.NewDevice()
	if err != nil {
		t.Fatalf("NewDevice(alice): %v", err)
	}

	msg := &protocol.PreKeyMessage{
		Version: protocol.CurrentVersion,
		Type:    protocol.MessageTypeRatchet,
	}

	if _, err := Respond(bobPrivateDevice, bobPrivateBundle, alicePublicDevice, msg); err == nil || !strings.Contains(err.Error(), "unexpected prekey message type") {
		t.Fatalf("expected unexpected type error, got %v", err)
	}
}

func TestRespondRejectsMissingRatchetMessage(t *testing.T) {
	fixture := newHandshakeFixture(t)
	fixture.preKeyMsg.Message = nil

	if _, err := Respond(fixture.bobPrivateDevice, fixture.bobPrivateBundle, fixture.alicePublicDevice, fixture.preKeyMsg); err == nil || !strings.Contains(err.Error(), "ratchet message is required") {
		t.Fatalf("expected missing ratchet message error, got %v", err)
	}
}

func TestRespondRejectsInvalidKeyLength(t *testing.T) {
	fixture := newHandshakeFixture(t)
	fixture.preKeyMsg.IKPub = []byte{1, 2, 3}

	if _, err := Respond(fixture.bobPrivateDevice, fixture.bobPrivateBundle, fixture.alicePublicDevice, fixture.preKeyMsg); err == nil || !strings.Contains(err.Error(), "invalid x448 key length") {
		t.Fatalf("expected invalid x448 key length error, got %v", err)
	}
}

func TestRespondRejectsInvalidKyberCiphertextSize(t *testing.T) {
	fixture := newHandshakeFixture(t)
	fixture.preKeyMsg.KyberCiphertext = []byte("bad")

	if _, err := Respond(fixture.bobPrivateDevice, fixture.bobPrivateBundle, fixture.alicePublicDevice, fixture.preKeyMsg); err == nil || !strings.Contains(err.Error(), "invalid ciphertext size") {
		t.Fatalf("expected invalid ciphertext size error, got %v", err)
	}
}

func TestRespondRejectsReusedPreKeyBundle(t *testing.T) {
	fixture := newHandshakeFixture(t)

	if _, err := Respond(fixture.bobPrivateDevice, fixture.bobPrivateBundle, fixture.alicePublicDevice, fixture.preKeyMsg); err != nil {
		t.Fatalf("first Respond: %v", err)
	}
	if !fixture.bobPrivateBundle.Consumed {
		t.Fatal("expected prekey bundle to be consumed after successful respond")
	}

	if _, err := Respond(fixture.bobPrivateDevice, fixture.bobPrivateBundle, fixture.alicePublicDevice, fixture.preKeyMsg); err == nil || !strings.Contains(err.Error(), "already consumed") {
		t.Fatalf("expected consumed bundle error, got %v", err)
	}
}
