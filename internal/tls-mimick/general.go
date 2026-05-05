package tlsmimick

type Extension interface {
	GetExtensionBytes() []byte
}

type HandshakeSegment struct {
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
