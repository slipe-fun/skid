package main

import (
	"encoding/hex"
	"fmt"

	"github.com/slipe-fun/skid/internal/crypto"
	"github.com/slipe-fun/skid/pkg/handshake"
	"github.com/slipe-fun/skid/pkg/identity"
	"github.com/slipe-fun/skid/pkg/protocol"
)

func main() {
	//bob

	bobPublicDevice, bobPrivateDevice, err := identity.NewDevice()
	if err != nil {
		panic(err)
	}

	bobPublicPreKeyBundle, bobPrivatePreKeyBundle, err := identity.NewPreKeyBundle(bobPublicDevice, bobPrivateDevice)
	if err != nil {
		panic(err)
	}

	//alice

	alicePublicDevice, alicePrivateDevice, err := identity.NewDevice()
	if err != nil {
		panic(err)
	}

	alicePublicPreKeyBundle, alicePrivatePreKeyBundle, err := identity.NewPreKeyBundle(alicePublicDevice, alicePrivateDevice)
	if err != nil {
		panic(err)
	}

	_ = alicePublicPreKeyBundle
	_ = alicePrivatePreKeyBundle

	aliceEK_Pub, aliceEK_Priv, err := crypto.GenerateECDHKeyPair()
	if err != nil {
		panic(err)
	}

	aliceSharedKey, aliceInitialMessage, err := handshake.Initiate(aliceEK_Pub, aliceEK_Priv, alicePublicDevice, alicePrivateDevice, bobPublicDevice, bobPublicPreKeyBundle)
	if err != nil {
		panic(err)
	}

	aliceDR, err := protocol.NewSessionInitiator(aliceSharedKey, bobPublicPreKeyBundle.SPK_Pub)
	if err != nil {
		panic(err)
	}

	chatKey, err := crypto.RandomBytes(32)
	if err != nil {
		panic(err)
	}

	aliceInitialMessage.Message, err = aliceDR.Encrypt(chatKey, alicePublicDevice.IK[:], bobPublicDevice.IK[:])
	if err != nil {
		panic(err)
	}

	fmt.Printf("Encrypted key: %s \n", hex.EncodeToString(chatKey))

	//bob

	bobSharedKey, err := handshake.Respond(bobPrivateDevice, bobPrivatePreKeyBundle, alicePublicDevice, aliceInitialMessage)
	if err != nil {
		panic(err)
	}

	bobDR := protocol.NewSessionResponder(bobSharedKey, bobPrivatePreKeyBundle.SPK_Priv)

	plain, err := bobDR.Decrypt(aliceInitialMessage.Message, alicePublicDevice.IK[:], bobPublicDevice.IK[:])
	if err != nil {
		panic(err)
	}

	fmt.Printf("Decrypted key: %s \n", hex.EncodeToString(plain))
}
