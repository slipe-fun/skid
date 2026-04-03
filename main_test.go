package main

import (
	"bytes"
	"testing"

	"github.com/slipe-fun/skid/internal/crypto"
	"github.com/slipe-fun/skid/pkg/handshake"
	"github.com/slipe-fun/skid/pkg/identity"
	"github.com/slipe-fun/skid/pkg/protocol"
)

func TestPreKeyMessageCarriesFirstRatchetMessage(t *testing.T) {
	bobPublicDevice, bobPrivateDevice, err := identity.NewDevice()
	if err != nil {
		t.Fatalf("NewDevice(bob): %v", err)
	}
	bobPublicPreKeyBundle, bobPrivatePreKeyBundle, err := identity.NewPreKeyBundle(bobPublicDevice, bobPrivateDevice)
	if err != nil {
		t.Fatalf("NewPreKeyBundle(bob): %v", err)
	}

	alicePublicDevice, alicePrivateDevice, err := identity.NewDevice()
	if err != nil {
		t.Fatalf("NewDevice(alice): %v", err)
	}

	aliceEKPub, aliceEKPriv, err := crypto.GenerateECDHKeyPair()
	if err != nil {
		t.Fatalf("GenerateECDHKeyPair(EK): %v", err)
	}

	aliceSharedKey, preKeyMessage, err := handshake.Initiate(aliceEKPub, aliceEKPriv, alicePublicDevice, alicePrivateDevice, bobPublicDevice, bobPublicPreKeyBundle)
	if err != nil {
		t.Fatalf("Initiate: %v", err)
	}

	aliceDR, err := protocol.NewSessionInitiator(aliceSharedKey, bobPublicPreKeyBundle.SPK_Pub)
	if err != nil {
		t.Fatalf("NewSessionInitiator: %v", err)
	}

	plaintext := []byte("hello from embedded message")
	preKeyMessage.Message, err = aliceDR.Encrypt(plaintext, alicePublicDevice.IK[:], bobPublicDevice.IK[:])
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if preKeyMessage.Message == nil {
		t.Fatal("expected embedded ratchet message")
	}

	bobSharedKey, err := handshake.Respond(bobPrivateDevice, bobPrivatePreKeyBundle, alicePublicDevice, preKeyMessage)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}

	bobDR := protocol.NewSessionResponder(bobSharedKey, bobPrivatePreKeyBundle.SPK_Priv)
	got, err := bobDR.Decrypt(preKeyMessage.Message, alicePublicDevice.IK[:], bobPublicDevice.IK[:])
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch: got %q want %q", got, plaintext)
	}
}
