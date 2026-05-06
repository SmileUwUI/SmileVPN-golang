package packets

import (
	"SmileVPN/internal/crypto"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

type TypePacket uint8

const (
	PlainPacket TypePacket = 0
	RawPacket   TypePacket = 1
)

type StreamingPacket struct {
	salt           []byte
	rawData        []byte
	plainData      []byte
	cipherData     []byte
	publicKey      []byte
	fakeFlag       bool
	ecdhFlag       bool
	disconnectFlag bool
	typePacket     TypePacket
}

func NewPlainPacket() (packet *StreamingPacket) {
	return &StreamingPacket{
		typePacket: PlainPacket,
		fakeFlag:   false,
		ecdhFlag:   false,
	}
}

func NewRawPacket() (packet *StreamingPacket) {
	return &StreamingPacket{
		typePacket: RawPacket,
		fakeFlag:   false,
		ecdhFlag:   false,
	}
}

func (s *StreamingPacket) AddData(data []byte) {
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	switch s.typePacket {
	case PlainPacket:
		s.plainData = append(s.plainData, dataCopy...)
	case RawPacket:
		s.rawData = append(s.rawData, dataCopy...)
	}
}

func (s *StreamingPacket) PackageAssembly(key, salt, publicKey []byte, fake, ecdh, disconnect bool) (err error) {
	if s.typePacket != PlainPacket {
		return errors.New("this operation is available only for the PlainPacket package type")
	}

	s.fakeFlag = fake
	s.ecdhFlag = ecdh
	s.publicKey = publicKey
	s.disconnectFlag = disconnect
	s.salt = salt
	var nonce []byte
	plainData := make([]byte, len(s.plainData)+len(salt)+len(s.publicKey))
	copy(plainData[:len(salt)], salt)
	if s.ecdhFlag {
		copy(plainData[len(salt):len(salt)+len(s.publicKey)], s.publicKey)
	}
	copy(plainData[len(salt)+len(s.publicKey):], s.plainData)

	s.cipherData, nonce, err = crypto.EncryptChaCha20Poly1305(plainData, key)
	if err != nil {
		return fmt.Errorf("packet decryption error: %v", err)
	}

	s.rawData = make([]byte, len(s.cipherData)+len(nonce)+2+1) // size CipherData + size Nonce + size length RawData + size length CipherData + size flags byte

	lenCipherData := len(s.cipherData) + len(nonce) + 2
	if lenCipherData < 0 {
		lenCipherData = 0
	}

	binary.BigEndian.PutUint16(s.rawData[1:3], uint16(lenCipherData))
	copy(s.rawData[3:15], nonce)
	copy(s.rawData[15:], s.cipherData)

	s.rawData = crypto.Trashfication(s.rawData, 300, 800)

	flagsBytes, err := crypto.RandomBytes(1)
	if err != nil {
		return fmt.Errorf("error generating random bytes: %v", err)
	}

	flags := flagsBytes[0] & 0b11110000
	if s.fakeFlag {
		flags = flags | 0b00000001
	}
	if s.ecdhFlag {
		flags = flags | 0b00000010
	}
	if len(salt) != 0 {
		flags = flags | 0b00000100
	}
	if s.disconnectFlag {
		flags = flags | 0b00001000
	}

	s.rawData[0] = flags ^ key[2]
	s.rawData[1] = s.rawData[1] ^ key[3]
	s.rawData[2] = s.rawData[2] ^ key[4]

	var rawDataWithtHeader bytes.Buffer
	rawDataWithtHeader.Write([]byte{0x17, 0x03, 0x03, uint8(len(s.rawData) >> 8), uint8(len(s.rawData))})
	rawDataWithtHeader.Write(s.rawData)

	s.rawData = rawDataWithtHeader.Bytes()

	return nil
}

func (s *StreamingPacket) DecodeAndDecrypt(key []byte) (err error) {
	if s.typePacket != RawPacket {
		return errors.New("this operation is available only for the RawPacket package type")
	}

	lengthCipherDataBytes := s.rawData[6:8]
	flags := s.rawData[5] ^ key[2]
	lengthCipherDataBytes[0] = lengthCipherDataBytes[0] ^ key[3]
	lengthCipherDataBytes[1] = lengthCipherDataBytes[1] ^ key[4]

	s.ecdhFlag = (flags>>1)&1 == 1
	s.fakeFlag = flags&1 == 1
	s.disconnectFlag = (flags>>3)&1 == 1
	if s.fakeFlag || s.disconnectFlag {
		return nil
	}

	lengthCipherData := binary.BigEndian.Uint16(lengthCipherDataBytes)
	s.cipherData = s.rawData[8 : lengthCipherData+6]

	s.plainData, err = crypto.DecryptChaCha20Poly1305(s.cipherData[12:], s.cipherData[:12], key)
	if err != nil {
		return fmt.Errorf("packet encryption error: %v", err)
	}

	offsetPlainData := 0
	if (flags>>2)&1 == 1 {
		s.salt = s.plainData[:8]
		offsetPlainData += 8
	}
	if s.ecdhFlag {
		s.publicKey = s.plainData[offsetPlainData : offsetPlainData+32]
		offsetPlainData += 32
	}
	s.plainData = s.plainData[offsetPlainData:]

	return nil
}

func (s *StreamingPacket) GetRawData() (data []byte) {
	return s.rawData
}

func (s *StreamingPacket) GetPlainData() (data []byte) {
	return s.plainData
}

func (s *StreamingPacket) GetSalt() (salt []byte) {
	return s.salt
}

func (s *StreamingPacket) GetPublicKey() (publicLey []byte) {
	return s.publicKey
}

func (s *StreamingPacket) GetEcdhFlag() (ecdhFlag bool) {
	return s.ecdhFlag
}

func (s *StreamingPacket) GetDisconnectFlag() (disconnectFlag bool) {
	return s.disconnectFlag
}

func (s *StreamingPacket) GetSlicePlainData(start, end int) (slicePlainData []byte, err error) {
	if start > end {
		return nil, errors.New("the start index cannot be greater than the end index")
	}

	if len(s.plainData) == 0 {
		return nil, errors.New("the size of `plainData` cannot be 0")
	}

	if start < 0 {
		return nil, errors.New("the starting index cannot be less than 0")
	}

	if end > len(s.plainData) {
		return nil, errors.New("the end index cannot exceed the packet length")
	}

	slicePlainData = s.plainData

	return slicePlainData[start:end], nil
}
