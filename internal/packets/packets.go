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
	rawData        []byte
	plainData      []byte
	cipherData     []byte
	parameters     map[string][]byte
	fakeFlag       bool
	disconnectFlag bool
	typePacket     TypePacket
}

func NewPlainPacket() (packet *StreamingPacket) {
	return &StreamingPacket{
		typePacket: PlainPacket,
		fakeFlag:   false,
		parameters: make(map[string][]byte),
	}
}

func NewRawPacket() (packet *StreamingPacket) {
	return &StreamingPacket{
		typePacket: RawPacket,
		fakeFlag:   false,
		parameters: make(map[string][]byte),
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

func (s *StreamingPacket) PackageAssembly(key []byte, fake, ecdh, disconnect bool) (err error) {
	if s.typePacket != PlainPacket {
		return errors.New("this operation is available only for the PlainPacket package type")
	}

	s.fakeFlag = fake
	s.disconnectFlag = disconnect

	var nonce []byte
	var plainData bytes.Buffer

	var parametersTable bytes.Buffer
	parametersTable.Write([]byte{0x00, 0x00})
	for key, value := range s.parameters {
		var rowData bytes.Buffer
		sizeKey := make([]byte, 2)
		binary.BigEndian.PutUint16(sizeKey, uint16(len(key)))
		rowData.Write(sizeKey)
		rowData.Write([]byte(key))
		rowData.Write(value)

		rowBytes := rowData.Bytes()
		sizeRow := make([]byte, 2)

		binary.BigEndian.PutUint16(sizeRow, uint16(len(rowBytes)))
		parametersTable.Write(sizeRow)
		parametersTable.Write(rowBytes)
	}

	parametersBytes := parametersTable.Bytes()
	sizeParameters := make([]byte, 2)
	binary.BigEndian.PutUint16(sizeParameters, uint16(len(parametersBytes))-2)
	parametersBytes[0] = sizeParameters[0]
	parametersBytes[1] = sizeParameters[1]

	plainData.Write(parametersBytes)
	plainData.Write(s.plainData)

	s.cipherData, nonce, err = crypto.EncryptChaCha20Poly1305(plainData.Bytes(), key)
	if err != nil {
		return fmt.Errorf("packet decryption error: %v", err)
	}

	lenCipherData := len(s.cipherData) + len(nonce) + 2
	if lenCipherData < 0 {
		lenCipherData = 0
	}

	rawData := bytes.NewBuffer([]byte{0x00, uint8(lenCipherData >> 8), uint8(lenCipherData)})

	rawData.Write(nonce)
	rawData.Write(s.cipherData)

	s.rawData = crypto.Trashfication(rawData.Bytes(), 300, 800)

	flagsBytes, err := crypto.RandomBytes(1)
	if err != nil {
		return fmt.Errorf("error generating random bytes: %v", err)
	}

	flags := flagsBytes[0] & 0b11111100
	if s.fakeFlag {
		flags = flags | 0b00000001
	}
	if s.disconnectFlag {
		flags = flags | 0b00000010
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
	rawData := bytes.NewBuffer(s.rawData)

	rawData.Next(5)
	flags, _ := rawData.ReadByte()
	lengthCipherDataBytes := make([]byte, 2)
	rawData.Read(lengthCipherDataBytes)

	flags = flags ^ key[2]
	lengthCipherDataBytes[0] = lengthCipherDataBytes[0] ^ key[3]
	lengthCipherDataBytes[1] = lengthCipherDataBytes[1] ^ key[4]

	s.fakeFlag = flags&1 == 1
	s.disconnectFlag = (flags>>1)&1 == 1
	if s.fakeFlag || s.disconnectFlag {
		return nil
	}

	lengthCipherData := binary.BigEndian.Uint16(lengthCipherDataBytes)
	s.cipherData = make([]byte, lengthCipherData-2)
	n, _ := rawData.Read(s.cipherData)
	if n < len(s.plainData) {
		return errors.New("invalid length")
	}

	s.plainData, err = crypto.DecryptChaCha20Poly1305(s.cipherData[12:], s.cipherData[:12], key)
	if err != nil {
		return fmt.Errorf("packet encryption error: %v", err)
	}

	plainDataBuffer := bytes.NewBuffer(s.plainData)
	sizeTableBytes := make([]byte, 2)
	_, err = plainDataBuffer.Read(sizeTableBytes)
	if err != nil {
		return fmt.Errorf("packet parsing parameters error: %v", err)
	}

	sizeTable := binary.BigEndian.Uint16(sizeTableBytes)
	parametersTableBytes := make([]byte, sizeTable)
	_, err = plainDataBuffer.Read(parametersTableBytes)
	if err != nil {
		return fmt.Errorf("packet parsing parameters error: %v", err)
	}

	var counterRowBytes uint16
	tableBuffer := bytes.NewBuffer(parametersTableBytes)
	counterRowBytes = 0
	for {
		if sizeTable == 0 {
			break
		}

		if counterRowBytes >= sizeTable {
			break
		}

		sizeRowBytes := make([]byte, 2)
		_, err = tableBuffer.Read(sizeRowBytes)
		if err != nil {
			break
		}
		sizeRow := binary.BigEndian.Uint16(sizeRowBytes)

		rowBytes := make([]byte, sizeRow)
		_, err = tableBuffer.Read(rowBytes)
		if err != nil {
			break
		}

		rowBuffer := bytes.NewBuffer(rowBytes)
		sizeKeyBytes := make([]byte, 2)
		_, err = rowBuffer.Read(sizeKeyBytes)
		if err != nil {
			break
		}
		sizeKey := binary.BigEndian.Uint16(sizeKeyBytes)

		keyBytes := make([]byte, sizeKey)
		_, err = rowBuffer.Read(keyBytes)
		if err != nil {
			break
		}
		key := string(keyBytes)

		value := make([]byte, rowBuffer.Len())
		_, err = rowBuffer.Read(value)
		if err != nil {
			break
		}

		counterRowBytes += 4 + sizeRow + sizeKey + uint16(len(value))

		s.parameters[key] = value
	}

	s.plainData = make([]byte, plainDataBuffer.Len())
	_, err = plainDataBuffer.Read(s.plainData)
	if err != nil {
		return fmt.Errorf("packet decryption error: %v", err)
	}
	return nil
}

func (s *StreamingPacket) AddParameter(key string, value []byte) {
	s.parameters[key] = value
}

func (s *StreamingPacket) GetRawData() (data []byte) {
	return s.rawData
}

func (s *StreamingPacket) GetPlainData() (data []byte) {
	return s.plainData
}

func (s *StreamingPacket) GetSalt() (salt []byte) {
	salt, ok := s.parameters["salt"]
	if !ok {
		return nil
	}
	return salt
}

func (s *StreamingPacket) GetPublicKey() (publicKey []byte) {
	publicKey, ok := s.parameters["publicKey"]
	if !ok {
		return nil
	}
	return publicKey
}

func (s *StreamingPacket) GetEcdhFlag() (ecdhFlag bool) {
	_, ok := s.parameters["publicKey"]
	return ok
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
