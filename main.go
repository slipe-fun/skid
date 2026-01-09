package main

import (
	"fmt"

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

	encrypted, err := protocol.Encrypt("Hello", alicePublicKeys, alicePrivateKeys, bobPublicKeys)
	if err != nil {
		panic(err)
	}

	authorDecrypted, err := protocol.Decrypt(encrypted, alicePublicKeys, alicePrivateKeys, alicePublicKeys, true)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Author decrypted message: %s\n", string(authorDecrypted))

	decrypted, err := protocol.Decrypt(encrypted, bobPublicKeys, bobPrivateKeys, alicePublicKeys, false)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Decrypted message: %s\n", string(decrypted))
}
