package conf

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/snell"
	"google.golang.org/protobuf/proto"
)

type SnellUser struct {
	PSK      string `json:"psk"`
	Version  uint32 `json:"version"`
	ObfsMode string `json:"obfsMode"`
	ObfsHost string `json:"obfsHost"`
	V6Mode   string `json:"v6Mode"`
	ClientID string `json:"clientId"`
	Level    byte   `json:"level"`
	Email    string `json:"email"`
}

type SnellServerConfig struct {
	Users []*SnellUser `json:"users"`
}

func (c *SnellServerConfig) Build() (proto.Message, error) {
	cfg := &snell.ServerConfig{
		Users: make([]*protocol.User, 0, len(c.Users)),
	}
	for _, u := range c.Users {
		if u.PSK == "" {
			return nil, errors.New("SNELL: user psk is required")
		}
		cfg.Users = append(cfg.Users, &protocol.User{
			Level: uint32(u.Level),
			Email: u.Email,
			Account: serial.ToTypedMessage(&snell.Account{
				Psk:      u.PSK,
				Version:  u.Version,
				ObfsMode: u.ObfsMode,
				ObfsHost: u.ObfsHost,
				V6Mode:   u.V6Mode,
				ClientId: u.ClientID,
			}),
		})
	}
	return cfg, nil
}

type SnellClientConfig struct {
	Address  *Address `json:"address"`
	Port     uint16   `json:"port"`
	Email    string   `json:"email"`
	PSK      string   `json:"psk"`
	Version  uint32   `json:"version"`
	ObfsMode string   `json:"obfsMode"`
	ObfsHost string   `json:"obfsHost"`
	V6Mode   string   `json:"v6Mode"`
	ClientID string   `json:"clientId"`
	Level    uint32   `json:"level"`
}

func (c *SnellClientConfig) Build() (proto.Message, error) {
	if c.Address == nil {
		return nil, errors.New("SNELL: server address is required")
	}
	if c.PSK == "" {
		return nil, errors.New("SNELL: psk is required")
	}
	return &snell.ClientConfig{
		Server: &protocol.ServerEndpoint{
			Address: c.Address.Build(),
			Port:    uint32(c.Port),
			User: &protocol.User{
				Level: c.Level,
				Email: c.Email,
				Account: serial.ToTypedMessage(&snell.Account{
					Psk:      c.PSK,
					Version:  c.Version,
					ObfsMode: c.ObfsMode,
					ObfsHost: c.ObfsHost,
					V6Mode:   c.V6Mode,
					ClientId: c.ClientID,
				}),
			},
		},
	}, nil
}
