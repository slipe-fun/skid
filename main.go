package main

import (
	"encoding/hex"
	"fmt"

	"github.com/slipe-fun/skid/internal/crypto"
	"github.com/slipe-fun/skid/pkg/identity"
	"github.com/slipe-fun/skid/pkg/protocol"
)

func main() {
	aliceSessionID := "5"
	alicePrivateKeys, alicePublicKeys, err := identity.NewUser()
	if err != nil {
		panic(err)
	}

	bobSessionID := "18"
	bobPrivateKeys, bobPublicKeys, err := identity.NewUser()
	if err != nil {
		panic(err)
	}

	chatKey, err := crypto.RandomBytes(32)
	if err != nil {
		panic(err)
	}

	epoch := uint32(1)

	encrypted, err := protocol.Encrypt(chatKey, epoch, alicePrivateKeys, alicePublicKeys, aliceSessionID, bobPublicKeys, bobSessionID)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Encrypted key: %s\n", hex.EncodeToString(chatKey))

	decrypted, err := protocol.Decrypt(encrypted, epoch, bobPrivateKeys, bobPublicKeys, bobSessionID, alicePublicKeys, aliceSessionID)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Decrypted key: %s\n", hex.EncodeToString(decrypted))
}
