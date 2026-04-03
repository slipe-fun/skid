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
	alicePublicPreKeyBundle, alicePrivatePreKeyBundle, err := identity.NewPreKeyBundle(alicePublicDevice, alicePrivateDevice)
	if err != nil {
		t.Fatalf("NewPreKeyBundle(alice): %v", err)
	}

	aliceEKPub, aliceEKPriv, err := crypto.GenerateECDHKeyPair()
	if err != nil {
		t.Fatalf("GenerateECDHKeyPair(EK): %v", err)
	}

	aliceSharedKey, preKeyMessage, err := handshake.Initiate(alicePublicPreKeyBundle.IK_Pub, alicePrivatePreKeyBundle.IK_Priv, aliceEKPub, aliceEKPriv, bobPublicPreKeyBundle)
	if err != nil {
		t.Fatalf("Initiate: %v", err)
	}

	aliceDR, err := protocol.NewSessionInitiator(aliceSharedKey, bobPublicPreKeyBundle.IK_Pub)
	if err != nil {
		t.Fatalf("NewSessionInitiator: %v", err)
	}

	plaintext := []byte("hello from embedded message")
	preKeyMessage.Message, err = aliceDR.Encrypt(plaintext, alicePublicPreKeyBundle.IK_Pub[:], bobPublicPreKeyBundle.IK_Pub[:])
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if preKeyMessage.Message == nil {
		t.Fatal("expected embedded ratchet message")
	}

	bobSharedKey, err := handshake.Respond(bobPrivatePreKeyBundle, preKeyMessage)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}

	bobDR := protocol.NewSessionResponder(bobSharedKey, bobPrivatePreKeyBundle.IK_Priv)
	got, err := bobDR.Decrypt(preKeyMessage.Message, alicePublicPreKeyBundle.IK_Pub[:], bobPublicPreKeyBundle.IK_Pub[:])
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch: got %q want %q", got, plaintext)
	}
}
