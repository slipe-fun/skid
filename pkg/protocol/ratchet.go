package protocol

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/dh/x448"
	"github.com/slipe-fun/skid/internal/crypto"
)

var (
	maxSkipMessagesLimit  = 2000
	maxSkippedKeysMapSize = 10000
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

func NewSessionInitiator(sharedKey []byte, bobRatchetPub x448.Key) (*Session, error) {
	s := &Session{
		rootKey:     sharedKey,
		remotePub:   bobRatchetPub,
		skippedKeys: make(map[string][]byte),
	}

	if _, err := rand.Read(s.localDH[:]); err != nil {
		return nil, fmt.Errorf("crypto/rand failed to generate local DH key: %w", err)
	}
	x448.KeyGen(&s.localPub, &s.localDH)

	var dhOut x448.Key
	if !x448.Shared(&dhOut, &s.localDH, &s.remotePub) {
		return nil, fmt.Errorf("ratchet initial DH failed: low-order point")
	}
	s.rootKey, s.sendCK = kdfRK(s.rootKey, dhOut[:])

	return s, nil
}

func NewSessionResponder(sharedKey []byte, bobRatchetPriv x448.Key) *Session {
	s := &Session{
		rootKey:     sharedKey,
		localDH:     bobRatchetPriv,
		skippedKeys: make(map[string][]byte),
	}

	x448.KeyGen(&s.localPub, &s.localDH)

	return s
}

func (s *Session) Encrypt(plaintext, aliceIK, bobIK []byte) (ciphertext, iv []byte, header *Header, err error) {
	if len(s.sendCK) == 0 {
		return nil, nil, nil, errors.New("cannot encrypt: session is not fully initialized")
	}
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
		if err := s.performRatchetStep(header); err != nil {
			return nil, err
		}
	}

	if header.Index > s.recvIdx {
		if err := s.skipMessages(header.Index); err != nil {
			return nil, err
		}
	}

	newCK, msgKey := kdfCK(s.recvCK)
	s.recvCK = newCK
	s.recvIdx++

	return crypto.Decrypt(msgKey, ciphertext, iv, aad)
}

func (s *Session) performRatchetStep(header *Header) error {
	s.prevMsg = s.sendIdx
	s.sendIdx = 0
	s.recvIdx = 0
	s.remotePub = header.RatchetPub

	var dhOut1 x448.Key
	if !x448.Shared(&dhOut1, &s.localDH, &s.remotePub) {
		return fmt.Errorf("ratchet step DH1 failed: low-order point")
	}
	s.rootKey, s.recvCK = kdfRK(s.rootKey, dhOut1[:])

	if _, err := rand.Read(s.localDH[:]); err != nil {
		return fmt.Errorf("crypto/rand failed to generate step DH key: %w", err)
	}
	x448.KeyGen(&s.localPub, &s.localDH)

	var dhOut2 x448.Key
	if !x448.Shared(&dhOut2, &s.localDH, &s.remotePub) {
		return fmt.Errorf("ratchet step DH2 failed: low-order point")
	}
	s.rootKey, s.sendCK = kdfRK(s.rootKey, dhOut2[:])

	return nil
}

func (s *Session) skipMessages(untilIndex uint32) error {
	if untilIndex <= s.recvIdx {
		return nil
	}

	count := untilIndex - s.recvIdx
	if count > uint32(maxSkipMessagesLimit) {
		return errors.New("too many messages to skip")
	}

	if len(s.skippedKeys)+int(count) > maxSkippedKeysMapSize {
		return errors.New("skipped keys map capacity exceeded")
	}

	for s.recvIdx < untilIndex {
		newCK, msgKey := kdfCK(s.recvCK)
		s.recvCK = newCK
		keyID := fmt.Sprintf("%x_%d", s.remotePub, s.recvIdx)
		s.skippedKeys[keyID] = msgKey
		s.recvIdx++
	}

	return nil
}

type Header struct {
	RatchetPub x448.Key
	Index      uint32
	PrevIdx    uint32
}
