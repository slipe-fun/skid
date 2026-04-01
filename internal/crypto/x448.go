package crypto

import (
	"crypto/rand"
	"errors"
	"io"

	"github.com/cloudflare/circl/dh/x448"
)

func GenerateECDHKeyPair() (x448.Key, x448.Key, error) {
	var pk, sk x448.Key

	if _, err := io.ReadFull(rand.Reader, sk[:]); err != nil {
		return x448.Key{}, x448.Key{}, errors.New("crypto/rand is unavailable: " + err.Error())
	}
	x448.KeyGen(&pk, &sk)

	return x448.Key(pk[:]), x448.Key(sk[:]), nil
}

func X3DH_Initiator(
	IKA_Priv x448.Key,
	EKA_Priv x448.Key,
	IKB_Pub x448.Key,
	SPKB_Pub x448.Key,
	OPKB_Pub x448.Key,
) (dh1, dh2, dh3, dh4 x448.Key) {

	x448.Shared(&dh1, &IKA_Priv, &SPKB_Pub)
	x448.Shared(&dh2, &EKA_Priv, &IKB_Pub)
	x448.Shared(&dh3, &EKA_Priv, &SPKB_Pub)
	x448.Shared(&dh4, &EKA_Priv, &OPKB_Pub)

	return
}

func X3DH_Responder(
	IKB_Priv x448.Key,
	SPKB_Priv x448.Key,
	OPKB_Priv x448.Key,
	IKA_Pub x448.Key,
	EKA_Pub x448.Key,
) (dh1, dh2, dh3, dh4 x448.Key) {

	x448.Shared(&dh1, &SPKB_Priv, &IKA_Pub)
	x448.Shared(&dh2, &IKB_Priv, &EKA_Pub)
	x448.Shared(&dh3, &SPKB_Priv, &EKA_Pub)
	x448.Shared(&dh4, &OPKB_Priv, &EKA_Pub)

	return
}
