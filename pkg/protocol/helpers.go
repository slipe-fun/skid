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

func GeneratePrekeyMessageBundle(prekey *PreKeyMessage) []byte {
	out := make([]byte, 0,
		16+
			1+
			1+
			len(prekey.SessionID)+
			len(prekey.IKPub)+
			len(prekey.EKPub)+
			len(prekey.KyberCiphertext),
	)

	out = append(out, []byte(PrekeyMessageBundleDomainPrefix)...)
	out = append(out, prekey.Version)
	out = append(out, prekey.Type)
	out = append(out, prekey.SessionID...)
	out = append(out, prekey.IKPub...)
	out = append(out, prekey.EKPub...)
	out = append(out, prekey.KyberCiphertext...)

	return out
}

func BuildPrekeyMessageBundleHash(prekey *PreKeyMessage) []byte {
	msg := GeneratePrekeyMessageBundle(prekey)
	sum := sha256.Sum256(msg)
	return sum[:]
}
