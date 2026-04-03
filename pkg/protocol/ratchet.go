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
	maxSkipMessagesLimit       = 2000
	maxSkippedKeysMapSize      = 10000
	errMessageAlreadyProcessed = errors.New("message index already processed")
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
		RootKey:     cloneBytes(s.rootKey),
		SendCK:      cloneBytes(s.sendCK),
		RecvCK:      cloneBytes(s.recvCK),
		LocalDH:     append([]byte(nil), s.localDH[:]...),
		LocalPub:    append([]byte(nil), s.localPub[:]...),
		RemotePub:   append([]byte(nil), s.remotePub[:]...),
		SendIdx:     s.sendIdx,
		RecvIdx:     s.recvIdx,
		PrevMsg:     s.prevMsg,
		SkippedKeys: cloneSkippedKeys(s.skippedKeys),
	}
}

func RestoreSession(state *SessionState) *Session {
	var localDH, localPub, remotePub x448.Key
	copy(localDH[:], state.LocalDH)
	copy(localPub[:], state.LocalPub)
	copy(remotePub[:], state.RemotePub)

	return &Session{
		rootKey:     cloneBytes(state.RootKey),
		sendCK:      cloneBytes(state.SendCK),
		recvCK:      cloneBytes(state.RecvCK),
		localDH:     localDH,
		localPub:    localPub,
		remotePub:   remotePub,
		sendIdx:     state.SendIdx,
		recvIdx:     state.RecvIdx,
		prevMsg:     state.PrevMsg,
		skippedKeys: cloneSkippedKeys(state.SkippedKeys),
	}
}

func cloneBytes(src []byte) []byte {
	return append([]byte(nil), src...)
}

func cloneSkippedKeys(src map[string][]byte) map[string][]byte {
	if len(src) == 0 {
		return make(map[string][]byte)
	}

	dst := make(map[string][]byte, len(src))
	for key, value := range src {
		dst[key] = cloneBytes(value)
	}

	return dst
}

func (s *Session) clone() *Session {
	if s == nil {
		return nil
	}

	return &Session{
		rootKey:     cloneBytes(s.rootKey),
		sendCK:      cloneBytes(s.sendCK),
		recvCK:      cloneBytes(s.recvCK),
		localDH:     s.localDH,
		localPub:    s.localPub,
		remotePub:   s.remotePub,
		sendIdx:     s.sendIdx,
		recvIdx:     s.recvIdx,
		prevMsg:     s.prevMsg,
		skippedKeys: cloneSkippedKeys(s.skippedKeys),
	}
}

func (s *Session) replace(next *Session) {
	s.rootKey = next.rootKey
	s.sendCK = next.sendCK
	s.recvCK = next.recvCK
	s.localDH = next.localDH
	s.localPub = next.localPub
	s.remotePub = next.remotePub
	s.sendIdx = next.sendIdx
	s.recvIdx = next.recvIdx
	s.prevMsg = next.prevMsg
	s.skippedKeys = next.skippedKeys
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
	working := s.clone()

	keyID := fmt.Sprintf("%x_%d", message.RatchetPub, message.Index)
	if key, ok := working.skippedKeys[keyID]; ok {
		plaintext, err := crypto.Decrypt(key, message.Ciphertext, message.Nonce, aad)
		if err != nil {
			return nil, err
		}
		delete(working.skippedKeys, keyID)
		s.replace(working)
		return plaintext, nil
	}

	if !bytes.Equal(message.RatchetPub, working.remotePub[:]) {
		if err := working.skipMessages(message.PrevIdx); err != nil {
			return nil, err
		}
		if err := working.performRatchetStep(remotePub); err != nil {
			return nil, err
		}
	}

	if message.Index < working.recvIdx {
		return nil, errMessageAlreadyProcessed
	}

	if message.Index > working.recvIdx {
		if err := working.skipMessages(message.Index); err != nil {
			return nil, err
		}
	}

	newCK, msgKey := kdfCK(working.recvCK)
	plaintext, err := crypto.Decrypt(msgKey, message.Ciphertext, message.Nonce, aad)
	if err != nil {
		return nil, err
	}

	working.recvCK = newCK
	working.recvIdx++
	s.replace(working)

	return plaintext, nil
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
