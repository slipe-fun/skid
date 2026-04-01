package protocol

import (
	"crypto/hmac"
	"crypto/sha256"
)

var (
	kdfSaltRK = []byte("DoubleRatchet-RootKey-Salt")
)

func kdfRK(rk, dhSecret []byte) (newRK, newCK []byte) {
	mac := hmac.New(sha256.New, rk)
	mac.Write(dhSecret)
	mac.Write(kdfSaltRK)
	res := mac.Sum(nil)
	return res[:32], res[32:]
}

func kdfCK(ck []byte) (newCK, msgKey []byte) {
	mac := hmac.New(sha256.New, ck)
	mac.Write([]byte{0x01})
	msgKey = mac.Sum(nil)
	mac.Reset()
	mac.Write([]byte{0x02})
	newCK = mac.Sum(nil)
	return
}
