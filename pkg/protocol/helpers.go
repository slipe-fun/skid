package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
)

var aadDomainPrefix = sha256.Sum256([]byte("SKID-PROTOCOL-V1-AAD"))

func GenerateAAD(
	header *Header,
	aliceIK, bobIK []byte,
) []byte {
	firstIK, secondIK := aliceIK, bobIK
	if bytes.Compare(aliceIK, bobIK) > 0 {
		firstIK, secondIK = bobIK, aliceIK
	}

	aad := make([]byte, 0, 208)

	aad = append(aad, aadDomainPrefix[:]...)

	aad = append(aad, firstIK...)
	aad = append(aad, secondIK...)

	aad = append(aad, header.RatchetPub[:]...)

	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, header.Index)
	aad = append(aad, buf...)

	binary.BigEndian.PutUint32(buf, header.PrevIdx)
	aad = append(aad, buf...)

	return aad
}
