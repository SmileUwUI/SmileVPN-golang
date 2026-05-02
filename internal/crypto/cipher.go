package crypto

import (
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

func EncryptChaCha20Poly1305(plainText, key []byte) (cipherText, nonce []byte, err error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, nil, fmt.Errorf("encryption error: %v", err)
	}

	nonce, err = RandomBytes(chacha20poly1305.NonceSize)
	if err != nil {
		return nil, nil, fmt.Errorf("")
	}

	cipherText = aead.Seal(nil, nonce, plainText, nil)

	return cipherText, nonce, nil
}

func DecryptChaCha20Poly1305(cipherText, nonce, key []byte) (plainText []byte, err error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("decryption error: %v", err)
	}

	plainText, err = aead.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption error: %v", err)
	}

	return plainText, nil
}
