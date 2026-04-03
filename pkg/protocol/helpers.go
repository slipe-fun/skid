package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
)

var (
	aadDomainPrefix                 = sha256.Sum256([]byte("SKID-PROTOCOL-V1-AAD"))
	PrekeyMessageBundleDomainPrefix = "SKID-PREKEY-V1"
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

func GeneratePrekeyMessageBundle(prekey *PreKeyMessage) []byte {
	out := make([]byte, 0, 192)

	out = append(out, []byte(PrekeyMessageBundleDomainPrefix)...)
	out = append(out, prekey.Version)
	out = append(out, prekey.Type)
	out = appendLengthPrefixedBytes(out, prekey.SessionID)
	out = appendLengthPrefixedBytes(out, prekey.IKPub)
	out = appendLengthPrefixedBytes(out, prekey.EKPub)
	out = appendLengthPrefixedBytes(out, prekey.KyberCiphertext)

	if prekey.Message == nil {
		out = append(out, 0)
		return out
	}

	out = append(out, 1)
	out = append(out, prekey.Message.Version)
	out = append(out, prekey.Message.Type)
	out = appendLengthPrefixedBytes(out, prekey.Message.SessionID)
	out = appendLengthPrefixedBytes(out, prekey.Message.RatchetPub)
	out = appendUint32(out, prekey.Message.Index)
	out = appendUint32(out, prekey.Message.PrevIdx)
	out = appendLengthPrefixedBytes(out, prekey.Message.Nonce)
	out = appendLengthPrefixedBytes(out, prekey.Message.Ciphertext)

	return out
}

func BuildPrekeyMessageBundleHash(prekey *PreKeyMessage) []byte {
	msg := GeneratePrekeyMessageBundle(prekey)
	sum := sha256.Sum256(msg)
	return sum[:]
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
