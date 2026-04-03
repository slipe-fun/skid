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

	aliceEK_Pub, aliceEK_Priv, err := crypto.GenerateECDHKeyPair()
	if err != nil {
		panic(err)
	}

	aliceSharedKey, aliceInitialMessage, err := handshake.Initiate(alicePublicPreKeyBundle.IK_Pub, alicePrivatePreKeyBundle.IK_Priv, aliceEK_Pub, aliceEK_Priv, bobPublicPreKeyBundle)
	if err != nil {
		panic(err)
	}

	aliceDR, err := protocol.NewSessionInitiator(aliceSharedKey, bobPublicPreKeyBundle.IK_Pub)
	if err != nil {
		panic(err)
	}

	chatKey, err := crypto.RandomBytes(32)
	if err != nil {
		panic(err)
	}

	aliceInitialMessage.Message, err = aliceDR.Encrypt(chatKey, alicePublicPreKeyBundle.IK_Pub[:], bobPublicPreKeyBundle.IK_Pub[:])
	if err != nil {
		panic(err)
	}

	fmt.Printf("Encrypted key: %s \n", hex.EncodeToString(chatKey))

	//bob

	bobSharedKey, err := handshake.Respond(bobPrivatePreKeyBundle, aliceInitialMessage)
	if err != nil {
		panic(err)
	}

	bobDR := protocol.NewSessionResponder(bobSharedKey, bobPrivatePreKeyBundle.IK_Priv)

	plain, err := bobDR.Decrypt(aliceInitialMessage.Message, alicePublicPreKeyBundle.IK_Pub[:], bobPublicPreKeyBundle.IK_Pub[:])
	if err != nil {
		panic(err)
	}

	fmt.Printf("Decrypted key: %s \n", hex.EncodeToString(plain))
}
