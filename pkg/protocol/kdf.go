package protocol

import (
	"crypto/hmac"
	"crypto/sha256"
)

var (
	kdfInfoRK = []byte("DoubleRatchet-RootKey-Salt")
)

func kdfRK(rk, dhSecret []byte) (newRK, newCK []byte) {
	macExtract := hmac.New(sha256.New, rk)
	macExtract.Write(dhSecret)
	prk := macExtract.Sum(nil)

	macT1 := hmac.New(sha256.New, prk)
	macT1.Write(kdfInfoRK)
	macT1.Write([]byte{0x01})
	newRK = macT1.Sum(nil)

	macT2 := hmac.New(sha256.New, prk)
	macT2.Write(newRK)
	macT2.Write(kdfInfoRK)
	macT2.Write([]byte{0x02})
	newCK = macT2.Sum(nil)

	return newRK, newCK
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
