package protocol

import (
	"fmt"

	ptls "github.com/Psiphon-Labs/psiphon-tls"
)

// EncryptionLevel is the encryption level
// Default value is Unencrypted
type EncryptionLevel uint8

const (
	// EncryptionInitial is the Initial encryption level
	EncryptionInitial EncryptionLevel = 1 + iota
	// EncryptionHandshake is the Handshake encryption level
	EncryptionHandshake
	// Encryption0RTT is the 0-RTT encryption level
	Encryption0RTT
	// Encryption1RTT is the 1-RTT encryption level
	Encryption1RTT
)

func (e EncryptionLevel) String() string {
	switch e {
	case EncryptionInitial:
		return "Initial"
	case EncryptionHandshake:
		return "Handshake"
	case Encryption0RTT:
		return "0-RTT"
	case Encryption1RTT:
		return "1-RTT"
	}
	return "unknown"
}

func (e EncryptionLevel) ToTLSEncryptionLevel() ptls.QUICEncryptionLevel {
	switch e {
	case EncryptionInitial:
		return ptls.QUICEncryptionLevelInitial
	case EncryptionHandshake:
		return ptls.QUICEncryptionLevelHandshake
	case Encryption1RTT:
		return ptls.QUICEncryptionLevelApplication
	case Encryption0RTT:
		return ptls.QUICEncryptionLevelEarly
	default:
		panic(fmt.Sprintf("unexpected encryption level: %s", e))
	}
}

func FromTLSEncryptionLevel(e ptls.QUICEncryptionLevel) EncryptionLevel {
	switch e {
	case ptls.QUICEncryptionLevelInitial:
		return EncryptionInitial
	case ptls.QUICEncryptionLevelHandshake:
		return EncryptionHandshake
	case ptls.QUICEncryptionLevelApplication:
		return Encryption1RTT
	case ptls.QUICEncryptionLevelEarly:
		return Encryption0RTT
	default:
		panic(fmt.Sprintf("unexpect encryption level: %s", e))
	}
}
