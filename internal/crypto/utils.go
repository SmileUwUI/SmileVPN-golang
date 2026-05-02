package crypto

import (
	cryptoRand "crypto/rand"
	"math/rand"
)

func RandomBytes(lengthOutput int) ([]byte, error) {
	output := make([]byte, lengthOutput)
	_, err := cryptoRand.Read(output)
	return output, err
}

func Trashfication(source []byte, minLength, maxLength int) (result []byte) {
	if minLength > maxLength {
		minLength, maxLength = maxLength, minLength
	}

	if len(source) >= maxLength {
		result = make([]byte, len(source))
		copy(result, source)
		return result
	}

	targetLen := len(source)

	if minLength > targetLen {
		targetLen = minLength
	}

	if targetLen < maxLength {
		// #nosec G404
		extra := rand.Intn(maxLength - targetLen + 1)
		targetLen += extra
	}

	result = make([]byte, targetLen)

	copy(result, source)

	for i := len(source); i < targetLen; i++ {
		// #nosec G115
		// #nosec G404
		result[i] = byte(rand.Intn(256))
	}

	return result
}
