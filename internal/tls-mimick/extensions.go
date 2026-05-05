package tlsmimick

import (
	"bytes"
	"encoding/binary"
	"fmt"
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
	result := make([]byte, 9+len(s.host))
	result[0] = 0x00
	result[1] = 0x00
	binary.BigEndian.PutUint16(result[2:4], uint16(len(s.host)+3+2))
	binary.BigEndian.PutUint16(result[4:6], uint16(len(s.host)+3))
	result[6] = 0x00
	binary.BigEndian.PutUint16(result[7:9], uint16(len(s.host)))
	copy(result[9:], []byte(s.host))

	return result
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
	result := make([]byte, 6+(len(s.groups)*2))
	result[0] = 0x00
	result[1] = 0x0a
	binary.BigEndian.PutUint16(result[2:4], uint16(2+(len(s.groups)*2)))
	binary.BigEndian.PutUint16(result[4:6], uint16(len(s.groups)*2))

	offset := 6
	for _, group := range s.groups {
		binary.BigEndian.PutUint16(result[offset:offset+2], group)
		offset += 2
	}

	return result
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
	result := make([]byte, 5+len(e.formats))
	result[0] = 0x00
	result[1] = 0x0b
	binary.BigEndian.PutUint16(result[2:4], uint16(1+len(e.formats)))
	result[4] = uint8(len(e.formats))

	offset := 5
	for _, format := range e.formats {
		result[offset] = format
		offset += 1
	}

	return result
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

	result := make([]byte, 6+len(a.protocols)+lenProtocolsString)
	result[0] = 0x00
	result[1] = 0x10
	binary.BigEndian.PutUint16(result[2:4], uint16(2+len(a.protocols)+lenProtocolsString))
	binary.BigEndian.PutUint16(result[4:6], uint16(len(a.protocols)+lenProtocolsString))

	offset := 6
	for _, protocol := range a.protocols {
		result[offset] = uint8(len(protocol))
		copy(result[offset+1:offset+1+len(protocol)], []byte(protocol))
		offset += 1 + len(protocol)
	}

	return result
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
	result := make([]byte, 6+(len(d.signatureHashAlgorithms)*2))
	result[0] = 0x00
	result[1] = 0x22
	binary.BigEndian.PutUint16(result[2:4], uint16(2+(len(d.signatureHashAlgorithms)*2)))
	binary.BigEndian.PutUint16(result[4:6], uint16(len(d.signatureHashAlgorithms)*2))

	offset := 6
	for _, algorithm := range d.signatureHashAlgorithms {
		binary.BigEndian.PutUint16(result[offset:offset+2], algorithm)
		offset += 2
	}

	return result
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
	var result []byte
	var offset int
	if len(k.entrys) > 1 {
		result = make([]byte, 6+(4*len(k.entrys))+lengthKeys)
		binary.BigEndian.PutUint16(result[2:4], uint16(2+(4*len(k.entrys))+lengthKeys))
		binary.BigEndian.PutUint16(result[4:6], uint16((4*len(k.entrys))+lengthKeys))
		offset = 6
	} else {
		result = make([]byte, 4+(4*len(k.entrys))+lengthKeys)
		binary.BigEndian.PutUint16(result[2:4], uint16(4*len(k.entrys)+lengthKeys))
		offset = 4
	}
	result[0] = 0x00
	result[1] = 0x33

	for _, key := range k.entrys {
		binary.BigEndian.PutUint16(result[offset:offset+2], key.Group)
		fmt.Printf("% x\n", key.Group)
		offset += 2
		binary.BigEndian.PutUint16(result[offset:offset+2], uint16(len(key.KeyExchange)))
		offset += 2
		copy(result[offset:offset+len(key.KeyExchange)], key.KeyExchange)
		offset += len(key.KeyExchange)
	}
	return result
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
	var offset int
	var result []byte
	if len(s.versions) > 1 {
		result = make([]byte, 5+(len(s.versions)*2))
		binary.BigEndian.PutUint16(result[2:4], uint16(1+(len(s.versions)*2)))
		result[4] = uint8(len(s.versions) * 2)
		offset = 5
	} else {
		result = make([]byte, 4+(len(s.versions)*2))
		binary.BigEndian.PutUint16(result[2:4], uint16(len(s.versions)*2))
		offset = 4
	}
	result[0] = 0x00
	result[1] = 0x2b

	for _, version := range s.versions {
		binary.BigEndian.PutUint16(result[offset:offset+2], version)
		offset += 2
	}
	return result
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
	result := make([]byte, 6+(len(s.signatureHashAlgorithms)*2))
	result[0] = 0x00
	result[1] = 0x0d
	binary.BigEndian.PutUint16(result[2:4], uint16(2+(len(s.signatureHashAlgorithms)*2)))
	binary.BigEndian.PutUint16(result[4:6], uint16(len(s.signatureHashAlgorithms)*2))

	offset := 6
	for _, algorithm := range s.signatureHashAlgorithms {
		binary.BigEndian.PutUint16(result[offset:offset+2], algorithm)
		offset += 2
	}

	return result
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
	result := make([]byte, 5+len(p.modes))
	result[0] = 0x00
	result[1] = 0x2d
	binary.BigEndian.PutUint16(result[2:4], uint16(1+len(p.modes)))
	result[4] = uint8(len(p.modes))

	offset := 5
	for _, mode := range p.modes {
		result[offset] = mode
		offset += 1
	}
	return result
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
	result := make([]byte, 6)
	result[0] = 0x00
	result[1] = 0x1c
	binary.BigEndian.PutUint16(result[2:4], uint16(2))
	binary.BigEndian.PutUint16(result[4:6], r.limit)

	return result
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
	result := make([]byte, 5+(len(c.algorithms)*2))
	result[0] = 0x00
	result[1] = 0x1b
	binary.BigEndian.PutUint16(result[2:4], uint16(1+(len(c.algorithms)*2)))
	result[4] = uint8(len(c.algorithms) * 2)

	offset := 5
	for _, algorithm := range c.algorithms {
		binary.BigEndian.PutUint16(result[offset:offset+2], algorithm)
		offset += 2
	}

	return result
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
