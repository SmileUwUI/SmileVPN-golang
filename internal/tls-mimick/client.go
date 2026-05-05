package tlsmimick

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
)

type ClientHello struct {
	Type             uint8
	Version          uint16
	Length           uint16
	HandshakeSegment *HandshakeSegment
}

var firefox150 = &ClientHello{
	Type:    0x16,
	Version: tls.VersionTLS10,
	Length:  0,
	HandshakeSegment: &HandshakeSegment{
		Type:               0x01,
		Length:             0,
		VersionTLS:         tls.VersionTLS12,
		Random:             [32]byte{},
		SessionIDLength:    32,
		SessionID:          [32]byte{},
		CipherSuitesLength: 32,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,                        // 0x1301
			tls.TLS_CHACHA20_POLY1305_SHA256,                  // 0x1303
			tls.TLS_AES_256_GCM_SHA384,                        // 0x1302
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,       // 0xc02b
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,         // 0xc02f
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, // 0xcca9
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,   // 0xcca8
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,       // 0xc02c
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,         // 0xc030
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,          // 0xc00a
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,            // 0xc013
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,            // 0xc014
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,               // 0x009c
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,               // 0x009d
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,                  // 0x002f
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,                  // 0x0035
		},
		CompressionMethodsLength: 1,
		CompressionMethods: []uint8{
			0x00, // null
		},
		ExtensionsLength: 0,
		Extensions:       []Extension{},
	},
}

func GetFirefox150(host string) *ClientHello {
	packet := firefox150

	packet.HandshakeSegment.Extensions = append(packet.HandshakeSegment.Extensions, CreateSNIExtension(host))
	packet.HandshakeSegment.Extensions = append(packet.HandshakeSegment.Extensions, CreateExtendedMasterSecret())
	packet.HandshakeSegment.Extensions = append(packet.HandshakeSegment.Extensions, CreateRenegotiationInfo())
	packet.HandshakeSegment.Extensions = append(packet.HandshakeSegment.Extensions, CreateSupportedGroups(
		[]uint16{
			uint16(tls.X25519MLKEM768), // 0x11ec
			uint16(tls.X25519),         // 0x001d
			0x0017,                     // secp256r1 0x0017
			0x0018,                     // secp384r1 0x0018
			0x0019,                     // secp521r1 0x0019
			0x0100,                     // ffdhe2048 0x0100
			0x0101,                     // ffdhe3072 0x0101
		}),
	)
	packet.HandshakeSegment.Extensions = append(packet.HandshakeSegment.Extensions, CreateECPointFormats([]uint8{0x00}))
	packet.HandshakeSegment.Extensions = append(packet.HandshakeSegment.Extensions, CreateSessionTicket())
	packet.HandshakeSegment.Extensions = append(packet.HandshakeSegment.Extensions, CreateALPN(
		[]string{
			"h2",
			"http/1.1",
		}),
	)
	packet.HandshakeSegment.Extensions = append(packet.HandshakeSegment.Extensions, CreateStatusRequest())
	packet.HandshakeSegment.Extensions = append(packet.HandshakeSegment.Extensions, CreateDelegetedCredentials(
		[]uint16{
			uint16(tls.ECDSAWithP256AndSHA256), // 0x0403
			uint16(tls.ECDSAWithP384AndSHA384), // 0x0503
			uint16(tls.ECDSAWithP521AndSHA512), // 0x0603
			uint16(tls.ECDSAWithSHA1),          // 0x0203
		}),
	)
	packet.HandshakeSegment.Extensions = append(packet.HandshakeSegment.Extensions, CreateSignedCertificateTimestamp())

	x25519 := make([]byte, 32)
	if _, err := rand.Read(x25519); err != nil {
		panic(err)
	}

	mlkem768 := make([]byte, 1216)
	copy(mlkem768[:32], x25519)
	if _, err := rand.Read(mlkem768); err != nil {
		panic(err)
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	publicKeyBytes, err := privateKey.PublicKey.Bytes()
	if err != nil {
		panic(err)
	}

	packet.HandshakeSegment.Extensions = append(packet.HandshakeSegment.Extensions, CreateKeyShare(
		[]*KeyShareEntry{
			{
				Group:       0x11ec, // X25519MLKEM768
				KeyExchange: mlkem768,
			},
			{
				Group:       0x001d, // X25519
				KeyExchange: x25519,
			},
			{
				Group:       0x0017, // SECP256R1
				KeyExchange: publicKeyBytes,
			},
		},
	))
	packet.HandshakeSegment.Extensions = append(packet.HandshakeSegment.Extensions, CreateSupportedVersions(
		[]uint16{
			tls.VersionTLS13,
			tls.VersionTLS12,
		},
	))
	packet.HandshakeSegment.Extensions = append(packet.HandshakeSegment.Extensions, CreateSignatureAlgorithms(
		[]uint16{
			uint16(tls.ECDSAWithP256AndSHA256), // 0x0403
			uint16(tls.ECDSAWithP384AndSHA384), // 0x0503
			uint16(tls.ECDSAWithP521AndSHA512), // 0x0603
			0x0804,                             // rsa_pss_rsae_sha256
			0x0805,                             // rsa_pss_rsae_sha384
			0x0806,                             // rsa_pss_rsae_sha512
			0x0401,                             // rsa_pkcs1_sha256
			0x0501,                             // rsa_pkcs1_sha384
			0x0601,                             // rsa_pkcs1_sha512
			0x0203,                             // ecdsa_sha1
			0x0201,                             // rsa_pkcs1_sha1
		},
	))
	packet.HandshakeSegment.Extensions = append(packet.HandshakeSegment.Extensions, CreatePSKKeyExchangeModes(
		[]uint8{
			0x01, // PSK with (EC)DHE key
		},
	))
	packet.HandshakeSegment.Extensions = append(packet.HandshakeSegment.Extensions, CreateRecordSizeLimit(16385))
	packet.HandshakeSegment.Extensions = append(packet.HandshakeSegment.Extensions, CreateCompressCertificate(
		[]uint16{
			0x0001, // zlib
			0x0002, // brotli
			0x0003, // zstd
		},
	))

	return packet
}

func (c *ClientHello) AssemblyClientHello() []byte {
	var (
		buf           bytes.Buffer
		extensionsBuf bytes.Buffer
	)
	buf.Write(
		[]byte{
			c.Type,
			byte(c.Version >> 8),
			byte(c.Version),
			byte(c.Length >> 8),
			byte(c.Length),
		},
	)
	buf.Write(
		[]byte{
			c.HandshakeSegment.Type,
			byte(c.HandshakeSegment.Length >> 16),
			byte(c.HandshakeSegment.Length >> 8),
			byte(c.HandshakeSegment.Length),
			byte(c.HandshakeSegment.VersionTLS >> 8),
			byte(c.HandshakeSegment.VersionTLS),
		},
	)

	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		panic(err)
	}
	buf.Write(random)
	buf.Write([]byte{c.HandshakeSegment.SessionIDLength})

	sessionID := make([]byte, c.HandshakeSegment.SessionIDLength)
	if _, err := rand.Read(sessionID); err != nil {
		panic(err)
	}
	buf.Write(sessionID)

	buf.Write([]byte{byte(c.HandshakeSegment.CipherSuitesLength >> 8), byte(c.HandshakeSegment.CipherSuitesLength)})
	for _, suite := range c.HandshakeSegment.CipherSuites {
		buf.Write([]byte{byte(suite >> 8), byte(suite)})
	}

	buf.Write([]byte{c.HandshakeSegment.CompressionMethodsLength})
	for _, method := range c.HandshakeSegment.CompressionMethods {
		buf.Write([]byte{method})
	}

	for _, extension := range c.HandshakeSegment.Extensions {
		extensionsBuf.Write(extension.GetExtensionBytes())
	}
	extensionsBytes := extensionsBuf.Bytes()
	lenExtension := len(extensionsBytes)
	buf.Write([]byte{byte(lenExtension >> 8), byte(lenExtension)})
	buf.Write(extensionsBytes)

	fin := buf.Bytes()

	lengthFin := uint16(len(fin) - 5)
	fin[3] = byte(lengthFin >> 8)
	fin[4] = byte(lengthFin)

	lengthHandshake := uint32(len(fin) - 9)
	fin[6] = byte(lengthHandshake >> 16)
	fin[7] = byte(lengthHandshake >> 8)
	fin[8] = byte(lengthHandshake)

	return fin
}
