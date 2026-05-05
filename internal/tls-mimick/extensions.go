package tlsmimick

import (
	"bytes"
	"encoding/binary"
)

type SNIExtension struct {
	host string
}

func CreateSNIExtension(host string) Extension {
	return SNIExtension{
		host: host,
	}
}

func (s SNIExtension) GetExtensionBytes() []byte {
	var result bytes.Buffer
	result.Write([]byte{0x00, 0x00})
	result.Write(uint16ToBytes(uint16(len(s.host) + 3 + 2)))
	result.Write(uint16ToBytes(uint16(len(s.host) + 3)))
	result.Write([]byte{0x00})
	result.Write(uint16ToBytes(uint16(len(s.host))))
	result.Write([]byte(s.host))

	return result.Bytes()
}

type ExtendedMasterSecret struct{}

func CreateExtendedMasterSecret() Extension {
	return ExtendedMasterSecret{}
}

func (e ExtendedMasterSecret) GetExtensionBytes() []byte {
	return []byte{0x00, 0x17, 0x00, 0x00}
}

type RenegotiationInfo struct{}

func CreateRenegotiationInfo() Extension {
	return RenegotiationInfo{}
}

func (e RenegotiationInfo) GetExtensionBytes() []byte {
	return []byte{0xff, 0x01, 0x00, 0x01, 0x00}
}

type SupportedGroups struct {
	groups []uint16
}

func CreateSupportedGroups(groups []uint16) Extension {
	return SupportedGroups{
		groups: groups,
	}
}

func (s SupportedGroups) GetExtensionBytes() []byte {
	var result bytes.Buffer
	result.Write([]byte{0x00, 0x0a})
	result.Write(uint16ToBytes(uint16(2 + (len(s.groups) * 2))))
	result.Write(uint16ToBytes(uint16(len(s.groups) * 2)))

	for _, group := range s.groups {
		result.Write(uint16ToBytes(uint16(group)))
	}

	return result.Bytes()
}

type ECPointFormats struct {
	formats []uint8
}

func CreateECPointFormats(formats []uint8) Extension {
	return ECPointFormats{
		formats: formats,
	}
}

func (e ECPointFormats) GetExtensionBytes() []byte {
	var result bytes.Buffer
	result.Write([]byte{0x00, 0x0b})
	result.Write(uint16ToBytes(uint16(1 + len(e.formats))))
	result.Write([]byte{uint8(len(e.formats))})

	for _, format := range e.formats {
		result.Write([]byte{format})
	}

	return result.Bytes()
}

type SessionTicket struct{}

func CreateSessionTicket() Extension {
	return SessionTicket{}
}

func (s SessionTicket) GetExtensionBytes() []byte {
	return []byte{0x00, 0x23, 0x00, 0x00}
}

type ALPN struct {
	protocols []string
}

func CreateALPN(protocols []string) Extension {
	return ALPN{
		protocols: protocols,
	}
}

func (a ALPN) GetExtensionBytes() []byte {
	lenProtocolsString := 0
	for _, protocol := range a.protocols {
		lenProtocolsString += len(protocol)
	}
	var result bytes.Buffer

	result.Write([]byte{0x00, 0x10})
	result.Write(uint16ToBytes(uint16(2 + len(a.protocols) + lenProtocolsString)))
	result.Write(uint16ToBytes(uint16(len(a.protocols) + lenProtocolsString)))

	for _, protocol := range a.protocols {
		result.Write([]byte{uint8(len(protocol))})
		result.Write([]byte(protocol))
	}

	return result.Bytes()
}

type StatusRequest struct{}

func CreateStatusRequest() Extension {
	return StatusRequest{}
}

func (s StatusRequest) GetExtensionBytes() []byte {
	return []byte{0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00}
}

type DelegetedCredentials struct {
	signatureHashAlgorithms []uint16
}

func CreateDelegetedCredentials(signatureHashAlgorithms []uint16) Extension {
	return DelegetedCredentials{
		signatureHashAlgorithms: signatureHashAlgorithms,
	}
}

func (d DelegetedCredentials) GetExtensionBytes() []byte {
	var result bytes.Buffer

	result.Write([]byte{0x00, 0x22})
	result.Write(uint16ToBytes(uint16(2 + (len(d.signatureHashAlgorithms) * 2))))
	result.Write(uint16ToBytes(uint16(len(d.signatureHashAlgorithms) * 2)))

	for _, algorithm := range d.signatureHashAlgorithms {
		result.Write(uint16ToBytes(algorithm))
	}

	return result.Bytes()
}

type SignedCertificateTimestamp struct{}

func CreateSignedCertificateTimestamp() Extension {
	return SignedCertificateTimestamp{}
}

func (s SignedCertificateTimestamp) GetExtensionBytes() []byte {
	return []byte{0x00, 0x12, 0x00, 0x00}
}

type KeyShareEntry struct {
	Group       uint16
	KeyExchange []byte
}

type KeyShare struct {
	entrys []*KeyShareEntry
}

func CreateKeyShare(entrys []*KeyShareEntry) Extension {
	return KeyShare{
		entrys: entrys,
	}
}

func (k KeyShare) GetExtensionBytes() []byte {
	lengthKeys := 0
	for _, entry := range k.entrys {
		lengthKeys += len(entry.KeyExchange)
	}
	var result bytes.Buffer

	result.Write([]byte{0x00, 0x33})
	if len(k.entrys) > 1 {
		result.Write(uint16ToBytes(uint16(2 + (4 * len(k.entrys)) + lengthKeys)))
		result.Write(uint16ToBytes(uint16((4 * len(k.entrys)) + lengthKeys)))
	} else {
		result.Write(uint16ToBytes(uint16(4*len(k.entrys) + lengthKeys)))
	}

	for _, key := range k.entrys {
		result.Write(uint16ToBytes(key.Group))
		result.Write(uint16ToBytes(uint16(len(key.KeyExchange))))
		result.Write(key.KeyExchange)
	}

	return result.Bytes()
}

type SupportedVersions struct {
	versions []uint16
}

func CreateSupportedVersions(versions []uint16) Extension {
	return SupportedVersions{
		versions: versions,
	}
}

func (s SupportedVersions) GetExtensionBytes() []byte {
	var result bytes.Buffer

	result.Write([]byte{0x00, 0x2b})
	if len(s.versions) > 1 {
		result.Write(uint16ToBytes(uint16(1 + (len(s.versions) * 2))))
		result.Write([]byte{uint8(len(s.versions) * 2)})
	} else {
		result.Write(uint16ToBytes(uint16(len(s.versions) * 2)))
	}

	for _, version := range s.versions {
		result.Write(uint16ToBytes(version))
	}

	return result.Bytes()
}

type SignatureAlgorithms struct {
	signatureHashAlgorithms []uint16
}

func CreateSignatureAlgorithms(signatureHashAlgorithms []uint16) Extension {
	return SignatureAlgorithms{
		signatureHashAlgorithms: signatureHashAlgorithms,
	}
}

func (s SignatureAlgorithms) GetExtensionBytes() []byte {
	var result bytes.Buffer

	result.Write([]byte{0x00, 0x0d})
	result.Write(uint16ToBytes(uint16(2 + (len(s.signatureHashAlgorithms) * 2))))
	result.Write(uint16ToBytes(uint16(len(s.signatureHashAlgorithms) * 2)))

	for _, algorithm := range s.signatureHashAlgorithms {
		result.Write(uint16ToBytes(algorithm))
	}

	return result.Bytes()
}

type PSKKeyExchangeModes struct {
	modes []uint8
}

func CreatePSKKeyExchangeModes(modes []uint8) Extension {
	return PSKKeyExchangeModes{
		modes: modes,
	}
}

func (p PSKKeyExchangeModes) GetExtensionBytes() []byte {
	var result bytes.Buffer

	result.Write([]byte{0x00, 0x2d})
	result.Write(uint16ToBytes(uint16(1 + len(p.modes))))
	result.Write([]byte{uint8(len(p.modes))})

	for _, mode := range p.modes {
		result.Write([]byte{mode})
	}
	return result.Bytes()
}

type RecordSizeLimit struct {
	limit uint16
}

func CreateRecordSizeLimit(limit uint16) Extension {
	return RecordSizeLimit{
		limit: limit,
	}
}

func (r RecordSizeLimit) GetExtensionBytes() []byte {
	var result bytes.Buffer

	result.Write([]byte{0x00, 0x1c, 0x00, 0x02})
	result.Write(uint16ToBytes(r.limit))

	return result.Bytes()
}

type CompressCertificate struct {
	algorithms []uint16
}

func CreateCompressCertificate(algorithms []uint16) Extension {
	return CompressCertificate{
		algorithms: algorithms,
	}
}

func (c CompressCertificate) GetExtensionBytes() []byte {
	var result bytes.Buffer

	result.Write([]byte{0x00, 0x1b})
	result.Write(uint16ToBytes(uint16(1 + (len(c.algorithms) * 2))))
	result.Write([]byte{uint8(len(c.algorithms) * 2)})

	for _, algorithm := range c.algorithms {
		result.Write(uint16ToBytes(uint16(algorithm)))
	}

	return result.Bytes()
}

type EncryptedClientHello struct {
	KDFId    uint16
	AEADId   uint16
	ConfigId uint8
	Enc      []byte
	Payload  []byte
}

func CreateEncryptedClientHello(KDFId, AEADId uint16, configId uint8, enc, payload []byte) Extension {
	return EncryptedClientHello{
		KDFId:    KDFId,
		AEADId:   AEADId,
		ConfigId: configId,
		Enc:      enc,
		Payload:  payload,
	}
}

func (e EncryptedClientHello) GetExtensionBytes() []byte {
	var result bytes.Buffer
	lengthEnc := len(e.Enc)
	lengthPayload := len(e.Payload)
	result.Write(
		[]byte{
			0xfe,
			0x0d,
			0x00,
			0x00,
			0x00,
			byte(e.KDFId >> 8),
			byte(e.KDFId),
			byte(e.AEADId >> 8),
			byte(e.AEADId),
			byte(e.ConfigId),
			byte(lengthEnc >> 8),
			byte(lengthEnc),
		},
	)

	result.Write(e.Enc)
	result.Write([]byte{byte(lengthPayload >> 8), byte(lengthPayload)})
	result.Write(e.Payload)

	fin := result.Bytes()
	fin[2] = byte((len(fin) - 4) >> 8)
	fin[3] = byte((len(fin) - 4))

	return fin
}

func uint16ToBytes(source uint16) []byte {
	result := make([]byte, 2)
	binary.BigEndian.PutUint16(result[0:2], source)
	return result
}
