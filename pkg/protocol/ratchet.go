package protocol

import (
	"bytes"
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

type SessionState struct {
	RootKey     []byte
	SendCK      []byte
	RecvCK      []byte
	LocalDH     []byte
	LocalPub    []byte
	RemotePub   []byte
	SendIdx     uint32
	RecvIdx     uint32
	PrevMsg     uint32
	SkippedKeys map[string][]byte
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

func (s *Session) Snapshot() *SessionState {
	return &SessionState{
		RootKey:     s.rootKey,
		SendCK:      s.sendCK,
		RecvCK:      s.recvCK,
		LocalDH:     s.localDH[:],
		LocalPub:    s.localPub[:],
		RemotePub:   s.remotePub[:],
		SendIdx:     s.sendIdx,
		RecvIdx:     s.recvIdx,
		PrevMsg:     s.prevMsg,
		SkippedKeys: s.skippedKeys,
	}
}

func RestoreSession(state *SessionState) *Session {
	return &Session{
		rootKey:     state.RootKey,
		sendCK:      state.SendCK,
		recvCK:      state.RecvCK,
		localDH:     x448.Key(state.LocalDH),
		localPub:    x448.Key(state.LocalPub),
		remotePub:   x448.Key(state.RemotePub),
		sendIdx:     state.SendIdx,
		recvIdx:     state.RecvIdx,
		prevMsg:     state.PrevMsg,
		skippedKeys: state.SkippedKeys,
	}
}

func (s *Session) Encrypt(plaintext, aliceIK, bobIK []byte) (*RatchetMessage, error) {
	if len(s.sendCK) == 0 {
		return nil, errors.New("cannot encrypt: session is not fully initialized")
	}
	newCK, msgKey := kdfCK(s.sendCK)
	s.sendCK = newCK

	message := &RatchetMessage{
		Version:    CurrentVersion,
		Type:       MessageTypeRatchet,
		RatchetPub: append([]byte(nil), s.localPub[:]...),
		Index:      s.sendIdx,
		PrevIdx:    s.prevMsg,
	}

	s.sendIdx++

	aad := GenerateAAD(message, aliceIK, bobIK)

	ciphertext, nonce, err := crypto.Encrypt(msgKey, plaintext, aad)
	if err != nil {
		return nil, err
	}

	message.Ciphertext = ciphertext
	message.Nonce = nonce

	return message, nil
}

func (s *Session) Decrypt(message *RatchetMessage, aliceIK, bobIK []byte) ([]byte, error) {
	if message == nil {
		return nil, errors.New("cannot decrypt: nil message")
	}
	if message.Version != CurrentVersion {
		return nil, fmt.Errorf("unsupported message version: %d", message.Version)
	}
	if message.Type != MessageTypeRatchet {
		return nil, fmt.Errorf("unexpected message type: %d", message.Type)
	}

	remotePub, err := decodeRatchetPub(message.RatchetPub)
	if err != nil {
		return nil, err
	}

	aad := GenerateAAD(message, aliceIK, bobIK)

	keyID := fmt.Sprintf("%x_%d", message.RatchetPub, message.Index)
	if key, ok := s.skippedKeys[keyID]; ok {
		plaintext, err := crypto.Decrypt(key, message.Ciphertext, message.Nonce, aad)
		if err != nil {
			return nil, err
		}
		delete(s.skippedKeys, keyID)
		return plaintext, nil
	}

	if !bytes.Equal(message.RatchetPub, s.remotePub[:]) {
		if err := s.performRatchetStep(remotePub); err != nil {
			return nil, err
		}
	}

	if message.Index > s.recvIdx {
		if err := s.skipMessages(message.Index); err != nil {
			return nil, err
		}
	}

	newCK, msgKey := kdfCK(s.recvCK)
	s.recvCK = newCK
	s.recvIdx++

	return crypto.Decrypt(msgKey, message.Ciphertext, message.Nonce, aad)
}

func (s *Session) performRatchetStep(remotePub x448.Key) error {
	s.prevMsg = s.sendIdx
	s.sendIdx = 0
	s.recvIdx = 0
	s.remotePub = remotePub

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

func decodeRatchetPub(pub []byte) (x448.Key, error) {
	var key x448.Key
	if len(pub) != len(key) {
		return x448.Key{}, fmt.Errorf("invalid ratchet public key length: got %d want %d", len(pub), len(key))
	}
	copy(key[:], pub)
	return key, nil
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
