package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
)

var (
	aadDomainPrefix = sha256.Sum256([]byte("SKID-PROTOCOL-V1-AAD"))
)

func GenerateAAD(
	message *RatchetMessage,
	aliceIK, bobIK []byte,
) []byte {
	firstIK, secondIK := aliceIK, bobIK
	if bytes.Compare(aliceIK, bobIK) > 0 {
		firstIK, secondIK = bobIK, aliceIK
	}

	aad := make([]byte, 0, 64+len(firstIK)+len(secondIK)+len(message.SessionID)+len(message.RatchetPub))

	aad = append(aad, aadDomainPrefix[:]...)

	aad = append(aad, firstIK...)
	aad = append(aad, secondIK...)

	aad = append(aad, message.Version)
	aad = append(aad, message.Type)
	aad = append(aad, message.SessionID...)
	aad = append(aad, message.RatchetPub...)

	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, message.Index)
	aad = append(aad, buf...)

	binary.BigEndian.PutUint32(buf, message.PrevIdx)
	aad = append(aad, buf...)

	return aad
}
