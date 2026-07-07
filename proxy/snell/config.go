package snell

import (
	"bytes"

	"github.com/xtls/xray-core/common/protocol"
	"google.golang.org/protobuf/proto"
)

// MemoryAccount 是运行期的 Snell 用户凭据。AEAD key 需在握手时结合每连接的 salt 用 Argon2id 派生,
// 故这里只保存原始 PSK 与版本/混淆选项。
type MemoryAccount struct {
	PSK      []byte
	Version  uint32
	ObfsMode string
	ObfsHost string
	V6Mode   string
	ClientID []byte
}

func (a *Account) AsAccount() (protocol.Account, error) {
	version := a.Version
	if version == 0 {
		version = protocolVersionDefault
	}
	return &MemoryAccount{
		PSK:      []byte(a.Psk),
		Version:  version,
		ObfsMode: a.ObfsMode,
		ObfsHost: a.ObfsHost,
		V6Mode:   a.V6Mode,
		ClientID: []byte(a.ClientId),
	}, nil
}

func (m *MemoryAccount) Equals(another protocol.Account) bool {
	if o, ok := another.(*MemoryAccount); ok {
		return bytes.Equal(m.PSK, o.PSK)
	}
	return false
}

func (m *MemoryAccount) ToProto() proto.Message {
	return &Account{
		Psk:      string(m.PSK),
		Version:  m.Version,
		ObfsMode: m.ObfsMode,
		ObfsHost: m.ObfsHost,
		V6Mode:   m.V6Mode,
		ClientId: string(m.ClientID),
	}
}
