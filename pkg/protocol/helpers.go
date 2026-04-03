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

	aad := make([]byte, 0, 96+len(firstIK)+len(secondIK)+len(message.SessionID)+len(message.RatchetPub))

	aad = append(aad, aadDomainPrefix[:]...)
	aad = appendLengthPrefixedBytes(aad, firstIK)
	aad = appendLengthPrefixedBytes(aad, secondIK)
	aad = append(aad, message.Version)
	aad = append(aad, message.Type)
	aad = appendLengthPrefixedBytes(aad, message.SessionID)
	aad = appendLengthPrefixedBytes(aad, message.RatchetPub)
	aad = appendUint32(aad, message.Index)
	aad = appendUint32(aad, message.PrevIdx)

	return aad
}
func appendLengthPrefixedBytes(dst, src []byte) []byte {
	dst = appendUint32(dst, uint32(len(src)))
	return append(dst, src...)
}

func appendUint32(dst []byte, value uint32) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], value)
	return append(dst, buf[:]...)
}
