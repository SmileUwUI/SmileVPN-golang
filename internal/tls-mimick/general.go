package tlsmimick

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
)

type Extension interface {
	GetExtensionBytes() []byte
}

type Record interface {
	GetBytes() []byte
}

type Packet struct {
	Records []Record
}

func (c *Packet) Assembly() []byte {
	var (
		buf bytes.Buffer
	)

	for _, record := range c.Records {
		buf.Write(record.GetBytes())
	}

	fin := buf.Bytes()

	return fin
}

type HandshakeRecord struct {
	RecordVersionTLS         uint16
	RecordLength             uint16
	Type                     uint8
	Length                   uint32 // only 24 bits
	VersionTLS               uint16
	Random                   [32]byte
	SessionIDLength          uint8
	SessionID                [32]byte
	CipherSuitesLength       uint16
	CipherSuites             []uint16
	CompressionMethodsLength uint8
	CompressionMethods       []uint8
	ExtensionsLength         uint16
	Extensions               []Extension
}

func (h HandshakeRecord) GetBytes() []byte {
	var (
		buf           bytes.Buffer
		extensionsBuf bytes.Buffer
	)
	buf.Write(
		[]byte{
			0x16,
			byte(h.RecordVersionTLS >> 8),
			byte(h.RecordVersionTLS),
			byte(h.RecordLength >> 8),
			byte(h.RecordLength),
			h.Type,
			byte(h.Length >> 16),
			byte(h.Length >> 8),
			byte(h.Length),
			byte(h.VersionTLS >> 8),
			byte(h.VersionTLS),
		},
	)

	// random := make([]byte, 32)
	random, _ := hex.DecodeString("df80b92f3016720b40b84ff557c6d70b46bc305bb8191513a55241d42dd66c75")
	// if _, err := rand.Read(random); err != nil {
	// 	panic(err)
	// }
	buf.Write(random)
	buf.Write([]byte{h.SessionIDLength})

	sessionID := make([]byte, h.SessionIDLength)
	if _, err := rand.Read(sessionID); err != nil {
		panic(err)
	}
	buf.Write(sessionID)

	switch h.Type {
	case 0x01:
		buf.Write([]byte{byte(h.CipherSuitesLength >> 8), byte(h.CipherSuitesLength)})
		for _, suite := range h.CipherSuites {
			buf.Write([]byte{byte(suite >> 8), byte(suite)})
		}
	case 0x02:
		buf.Write([]byte{byte(h.CipherSuites[0] >> 8), byte(h.CipherSuites[0])})
	}

	switch h.Type {
	case 0x01:
		buf.Write([]byte{h.CompressionMethodsLength})
		for _, method := range h.CompressionMethods {
			buf.Write([]byte{method})
		}
	case 0x02:
		buf.Write([]byte{h.CompressionMethods[0]})
	}

	for _, extension := range h.Extensions {
		extensionsBuf.Write(extension.GetExtensionBytes())
	}
	extensionsBytes := extensionsBuf.Bytes()
	lenExtension := len(extensionsBytes)
	buf.Write([]byte{byte(lenExtension >> 8), byte(lenExtension)})
	buf.Write(extensionsBytes)

	fin := buf.Bytes()
	lengthFin := uint32(len(fin))
	fin[3] = byte((lengthFin - 5) >> 8)
	fin[4] = byte((lengthFin - 5))

	fin[6] = byte((lengthFin - 9) >> 16)
	fin[7] = byte((lengthFin - 9) >> 8)
	fin[8] = byte((lengthFin - 9))

	return fin
}

type ChangeCipherSpec struct{}

func (c ChangeCipherSpec) GetBytes() []byte {
	return []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}
}
