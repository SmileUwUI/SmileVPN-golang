package tlsmimick

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
)

func GetHelloRecordFirefox150(host string) *Packet {
	handshakeRecordFirefox150 := &HandshakeRecord{
		RecordVersionTLS:   tls.VersionTLS10,
		RecordLength:       0,
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
	}

	handshakeRecordFirefox150.Extensions = append(handshakeRecordFirefox150.Extensions, CreateSNIExtension(host))
	handshakeRecordFirefox150.Extensions = append(handshakeRecordFirefox150.Extensions, CreateExtendedMasterSecret())
	handshakeRecordFirefox150.Extensions = append(handshakeRecordFirefox150.Extensions, CreateRenegotiationInfo())
	handshakeRecordFirefox150.Extensions = append(handshakeRecordFirefox150.Extensions, CreateSupportedGroups(
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
	handshakeRecordFirefox150.Extensions = append(handshakeRecordFirefox150.Extensions, CreateECPointFormats([]uint8{0x00}))
	// handshakeRecordFirefox150.Extensions = append(handshakeRecordFirefox150.Extensions, CreateSessionTicket())
	handshakeRecordFirefox150.Extensions = append(handshakeRecordFirefox150.Extensions, CreateALPN(
		[]string{
			"h2",
			"http/1.1",
		}),
	)
	handshakeRecordFirefox150.Extensions = append(handshakeRecordFirefox150.Extensions, CreateStatusRequest())
	handshakeRecordFirefox150.Extensions = append(handshakeRecordFirefox150.Extensions, CreateDelegetedCredentials(
		[]uint16{
			uint16(tls.ECDSAWithP256AndSHA256), // 0x0403
			uint16(tls.ECDSAWithP384AndSHA384), // 0x0503
			uint16(tls.ECDSAWithP521AndSHA512), // 0x0603
			uint16(tls.ECDSAWithSHA1),          // 0x0203
		}),
	)
	handshakeRecordFirefox150.Extensions = append(handshakeRecordFirefox150.Extensions, CreateSignedCertificateTimestamp())

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

	handshakeRecordFirefox150.Extensions = append(handshakeRecordFirefox150.Extensions, CreateKeyShare(
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
	handshakeRecordFirefox150.Extensions = append(handshakeRecordFirefox150.Extensions, CreateSupportedVersions(
		[]uint16{
			tls.VersionTLS13,
			tls.VersionTLS12,
		},
	))
	handshakeRecordFirefox150.Extensions = append(handshakeRecordFirefox150.Extensions, CreateSignatureAlgorithms(
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
	// handshakeRecordFirefox150.Extensions = append(handshakeRecordFirefox150.Extensions, CreatePSKKeyExchangeModes(
	// 	[]uint8{
	// 		0x01, // PSK with (EC)DHE key
	// 	},
	// ))
	handshakeRecordFirefox150.Extensions = append(handshakeRecordFirefox150.Extensions, CreateRecordSizeLimit(16385))
	handshakeRecordFirefox150.Extensions = append(handshakeRecordFirefox150.Extensions, CreateCompressCertificate(
		[]uint16{
			0x0001, // zlib
			0x0002, // brotli
			0x0003, // zstd
		},
	))
	configId := make([]byte, 1)
	if _, err := rand.Read(configId); err != nil {
		panic(err)
	}

	enc := make([]byte, 32)
	if _, err := rand.Read(enc); err != nil {
		panic(err)
	}

	payload := make([]byte, 239)
	if _, err := rand.Read(payload); err != nil {
		panic(err)
	}
	handshakeRecordFirefox150.Extensions = append(handshakeRecordFirefox150.Extensions, CreateEncryptedClientHello(
		0x0001,
		0x0001,
		configId[0],
		enc,
		payload,
	))

	packet := &Packet{
		Records: []Record{
			handshakeRecordFirefox150,
		},
	}

	return packet
}
