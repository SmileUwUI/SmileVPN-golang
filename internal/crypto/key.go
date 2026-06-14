package crypto

import (
	"hash"
	"sync"
)

type Key struct {
	keyBytes []byte
	hasher   hash.Hash
	mu       sync.RWMutex
}

func NewKey(hasher hash.Hash) *Key {
	return &Key{
		keyBytes: []byte{},
		hasher:   hasher,
	}
}

func (k *Key) SetKey(key []byte) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.keyBytes = key
}

func (k *Key) UpdateKey(salt []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	k.hasher.Reset()

	if _, err := k.hasher.Write(k.keyBytes); err != nil {
		return err
	}
	if _, err := k.hasher.Write([]byte(":")); err != nil {
		return err
	}
	if _, err := k.hasher.Write(salt); err != nil {
		return err
	}

	k.keyBytes = k.hasher.Sum(nil)
	return nil
}

func (k *Key) GetBytes() []byte {
	k.mu.RLock()
	defer k.mu.RUnlock()

	bytes := make([]byte, len(k.keyBytes))
	copy(bytes, k.keyBytes)
	return bytes
}
