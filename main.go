package main

import (
	"fmt"

	"github.com/slipe-fun/skid/internal/crypto"
	"github.com/slipe-fun/skid/pkg/identity"
	"github.com/slipe-fun/skid/pkg/protocol"
)

func main() {
	alicePrivateKeys, alicePublicKeys, err := identity.NewUser()
	if err != nil {
		panic(err)
	}

	bobPrivateKeys, bobPublicKeys, err := identity.NewUser()
	if err != nil {
		panic(err)
	}

	chatKey, err := crypto.RandomBytes(32)
	if err != nil {
		panic(err)
	}

	lastSecuence := uint64(1734)

	encrypted, err := protocol.Encrypt(chatKey, lastSecuence, alicePrivateKeys, bobPublicKeys)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Encrypted key: %s\n", string(chatKey))

	decrypted, err := protocol.Decrypt(encrypted, lastSecuence, bobPrivateKeys, bobPublicKeys, alicePublicKeys)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Decrypted key: %s\n", string(decrypted))
}
