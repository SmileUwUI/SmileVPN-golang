package tlsmimick

import (
	"crypto/rand"
	"crypto/tls"
)

func GetServerHelloPattern1() *Packet {
	handshakeRecord := &HandshakeRecord{
		RecordVersionTLS: tls.VersionTLS12,
		Type:             0x02,
		Length:           0,
		VersionTLS:       tls.VersionTLS12,
		SessionIDLength:  32,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256, // 0x1301
		},
		CompressionMethods: []uint8{
			0x00, // null
		},
		ExtensionsLength: 0,
		Extensions:       []Extension{},
	}

	x25519 := make([]byte, 32)
	if _, err := rand.Read(x25519); err != nil {
		panic(err)
	}
	handshakeRecord.Extensions = append(handshakeRecord.Extensions, CreateKeyShare(
		[]*KeyShareEntry{
			{
				Group:       0x001d, // X25519
				KeyExchange: x25519,
			},
		},
	))
	handshakeRecord.Extensions = append(handshakeRecord.Extensions, CreateSupportedVersions(
		[]uint16{
			tls.VersionTLS13,
		},
	))

	packet := &Packet{
		Records: []Record{
			handshakeRecord,
			&ChangeCipherSpec{},
		},
	}

	return packet
}
