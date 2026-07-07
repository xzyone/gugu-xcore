// Package snell 实现 Snell 代理协议(v4/v5)的 inbound 服务端与 outbound 客户端。
//
// Snell 是 Surge 的轻量代理协议:PSK 经 Argon2id 派生出 AES-128-GCM key,数据走 length-prefixed
// AEAD record,首个 record 前置 16B salt。地址用 host-string 编码,UDP 走 UDP-over-TCP(CommandUDP)。
// 多用户:服务端用每个用户的 PSK 逐一试解首个 record(与 shadowsocks AEAD 同理)。
//
// v6 的流量整形(Traffic Shaping)不在本文件范围。
package snell

import (
	"context"

	"github.com/xtls/xray-core/common"
)

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
}
