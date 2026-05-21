package proxy

import (
	"context"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

// VisionLimiterFunc 是 vision splice 触发时的 conn-wrap 钩子。
// 触发时机:VisionReader.ReadMultiBuffer / VisionWriter.WriteMultiBuffer 切换到 directCopy 那一刻,
// xray-core 调 UnwrapRawConn 拿到底层 net.Conn 后会调本钩子;
// 实现方(mmw-agent)可以根据 email 查 per-user rate limiter,把 rawConn 包一层 throttling conn 返回。
//
// 钩子返回 nil 或返回 rawConn 本身 → vision 走原路径(零拷贝、不限速)。
// 返回新 conn → vision 后续 raw IO 全部经过该 conn,逃不掉 user-space 节流。
//
// 这个钩子只对启用 xtls-rprx-vision 的连接生效;其他协议的限速仍走 mmw-agent dispatcher 标准 RateWriter 路径。
type VisionLimiterFunc func(email string, rawConn net.Conn) net.Conn

var visionLimiterHook VisionLimiterFunc

// SetVisionLimiterHook 安装 vision splice 时的 conn wrap 钩子。覆盖式注册,nil 表示卸载。
//
// xray:api:beta
func SetVisionLimiterHook(fn VisionLimiterFunc) { visionLimiterHook = fn }

// maybeWrapVisionConn 在 ctx 能解出 user.Email 且 hook 已注册时,把 rawConn 包成限速 conn;
// 否则原样返回。
func maybeWrapVisionConn(ctx context.Context, conn net.Conn) net.Conn {
	if visionLimiterHook == nil || conn == nil {
		return conn
	}
	inb := session.InboundFromContext(ctx)
	if inb == nil || inb.User == nil || inb.User.Email == "" {
		return conn
	}
	if wrapped := visionLimiterHook(inb.User.Email, conn); wrapped != nil {
		return wrapped
	}
	return conn
}
