package protocol

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/dh/x448"
	"github.com/slipe-fun/skid/internal/crypto"
)

type Session struct {
	rootKey []byte
	sendCK  []byte
	recvCK  []byte

	localDH   x448.Key
	localPub  x448.Key
	remotePub x448.Key

	sendIdx uint32
	recvIdx uint32
	prevMsg uint32

	skippedKeys map[string][]byte
}

func NewSession(sharedKey []byte, remoteIdentityPub x448.Key, isInitiator bool) *Session {
	s := &Session{
		rootKey:     sharedKey,
		remotePub:   remoteIdentityPub,
		skippedKeys: make(map[string][]byte),
	}

	rand.Read(s.localDH[:])
	x448.KeyGen(&s.localPub, &s.localDH)

	if isInitiator {
		var dhOut x448.Key
		x448.Shared(&dhOut, &s.localDH, &s.remotePub)
		s.rootKey, s.sendCK = kdfRK(s.rootKey, dhOut[:])
	}
	return s
}

func (s *Session) Encrypt(plaintext, aliceIK, bobIK []byte) (ciphertext, iv []byte, header *Header, err error) {
	newCK, msgKey := kdfCK(s.sendCK)
	s.sendCK = newCK

	header = &Header{
		RatchetPub: s.localPub,
		Index:      s.sendIdx,
		PrevIdx:    s.prevMsg,
	}

	s.sendIdx++

	aad := GenerateAAD(header, aliceIK, bobIK)

	ciphertext, iv, err = crypto.Encrypt(msgKey, plaintext, aad)
	return
}

func (s *Session) Decrypt(ciphertext, iv []byte, header *Header, aliceIK, bobIK []byte) ([]byte, error) {
	aad := GenerateAAD(header, aliceIK, bobIK)

	keyID := fmt.Sprintf("%x_%d", header.RatchetPub, header.Index)
	if key, ok := s.skippedKeys[keyID]; ok {
		delete(s.skippedKeys, keyID)
		return crypto.Decrypt(key, ciphertext, iv, aad)
	}

	if header.RatchetPub != s.remotePub {
		s.performRatchetStep(header)
	}

	if header.Index > s.recvIdx {
		s.skipMessages(header.Index)
	}

	newCK, msgKey := kdfCK(s.recvCK)
	s.recvCK = newCK
	s.recvIdx++

	return crypto.Decrypt(msgKey, ciphertext, iv, aad)
}

func (s *Session) performRatchetStep(header *Header) {
	s.prevMsg = s.sendIdx
	s.sendIdx = 0
	s.recvIdx = 0
	s.remotePub = header.RatchetPub

	var dhOut1 x448.Key
	x448.Shared(&dhOut1, &s.localDH, &s.remotePub)
	s.rootKey, s.recvCK = kdfRK(s.rootKey, dhOut1[:])

	rand.Read(s.localDH[:])
	x448.KeyGen(&s.localPub, &s.localDH)

	var dhOut2 x448.Key
	x448.Shared(&dhOut2, &s.localDH, &s.remotePub)
	s.rootKey, s.sendCK = kdfRK(s.rootKey, dhOut2[:])
}

func (s *Session) skipMessages(untilIndex uint32) {
	for s.recvIdx < untilIndex {
		newCK, msgKey := kdfCK(s.recvCK)
		s.recvCK = newCK
		keyID := fmt.Sprintf("%x_%d", s.remotePub, s.recvIdx)
		s.skippedKeys[keyID] = msgKey
		s.recvIdx++
	}
}

type Header struct {
	RatchetPub x448.Key
	Index      uint32
	PrevIdx    uint32
}
