package snell

import (
	"encoding/binary"
	"sync"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
)

// UDP 地址编码(对齐 sing-snell address.go):
//   - 请求(client→server): 域名 = len|host|port;IP = 0x00|family|ip|port
//   - 响应(server→client): 仅 IP = family|ip|port(无 0x00 前缀、无命令字节)
// family: 0x04=IPv4, 0x06=IPv6。端口 2 字节大端。每个数据报独占一个 record,明文首字节:
//   - 请求 record: UDPCommandForward(0x01) 后接请求地址
//   - 响应 record: 直接响应地址

const udpCommandForward = 0x01

// appendUDPRequestAddress 追加请求地址(client→server)。
func appendUDPRequestAddress(dst []byte, dest net.Destination) ([]byte, error) {
	addr := dest.Address
	if addr.Family().IsDomain() {
		host := addr.Domain()
		if len(host) == 0 || len(host) > 255 {
			return nil, errors.New("snell: invalid udp host: ", host)
		}
		dst = append(dst, byte(len(host)))
		dst = append(dst, host...)
	} else {
		dst = append(dst, 0x00)
		if addr.Family().IsIPv4() {
			dst = append(dst, addressTypeIPv4)
			dst = append(dst, addr.IP()...)
		} else {
			dst = append(dst, addressTypeIPv6)
			dst = append(dst, addr.IP()...)
		}
	}
	return binary.BigEndian.AppendUint16(dst, uint16(dest.Port)), nil
}

// readUDPRequestAddress 解析请求地址(server 端),返回目标与剩余 payload。
func readUDPRequestAddress(b []byte) (net.Destination, []byte, error) {
	if len(b) < 1 {
		return net.Destination{}, nil, errors.New("snell: short udp request address")
	}
	first := b[0]
	if first != 0x00 {
		hl := int(first)
		if len(b) < 1+hl+2 {
			return net.Destination{}, nil, errors.New("snell: short udp domain address")
		}
		host := string(b[1 : 1+hl])
		port := binary.BigEndian.Uint16(b[1+hl : 1+hl+2])
		return net.UDPDestination(net.ParseAddress(host), net.Port(port)), b[1+hl+2:], nil
	}
	if len(b) < 2 {
		return net.Destination{}, nil, errors.New("snell: short udp ip address")
	}
	switch b[1] {
	case addressTypeIPv4:
		if len(b) < 2+4+2 {
			return net.Destination{}, nil, errors.New("snell: short udp ipv4")
		}
		ip := net.IPAddress(b[2:6])
		port := binary.BigEndian.Uint16(b[6:8])
		return net.UDPDestination(ip, net.Port(port)), b[8:], nil
	case addressTypeIPv6:
		if len(b) < 2+16+2 {
			return net.Destination{}, nil, errors.New("snell: short udp ipv6")
		}
		ip := net.IPAddress(b[2:18])
		port := binary.BigEndian.Uint16(b[18:20])
		return net.UDPDestination(ip, net.Port(port)), b[20:], nil
	default:
		return net.Destination{}, nil, errors.New("snell: unknown udp address family ", b[1])
	}
}

// appendUDPResponseAddress 追加响应地址(server→client,仅 IP)。
func appendUDPResponseAddress(dst []byte, source net.Destination) ([]byte, error) {
	addr := source.Address
	if addr.Family().IsDomain() {
		return nil, errors.New("snell: udp response source is not ip")
	}
	if addr.Family().IsIPv4() {
		dst = append(dst, addressTypeIPv4)
		dst = append(dst, addr.IP()...)
	} else {
		dst = append(dst, addressTypeIPv6)
		dst = append(dst, addr.IP()...)
	}
	return binary.BigEndian.AppendUint16(dst, uint16(source.Port)), nil
}

// readUDPResponseAddress 解析响应地址(client 端),返回来源与剩余 payload。
func readUDPResponseAddress(b []byte) (net.Destination, []byte, error) {
	if len(b) < 1 {
		return net.Destination{}, nil, errors.New("snell: short udp response address")
	}
	switch b[0] {
	case addressTypeIPv4:
		if len(b) < 1+4+2 {
			return net.Destination{}, nil, errors.New("snell: short udp response ipv4")
		}
		ip := net.IPAddress(b[1:5])
		port := binary.BigEndian.Uint16(b[5:7])
		return net.UDPDestination(ip, net.Port(port)), b[7:], nil
	case addressTypeIPv6:
		if len(b) < 1+16+2 {
			return net.Destination{}, nil, errors.New("snell: short udp response ipv6")
		}
		ip := net.IPAddress(b[1:17])
		port := binary.BigEndian.Uint16(b[17:19])
		return net.UDPDestination(ip, net.Port(port)), b[19:], nil
	default:
		return net.Destination{}, nil, errors.New("snell: unknown udp response family ", b[0])
	}
}

// udpPacketWriter 把一个数据报(地址+payload)编码为单个 record 写出。
// 多个 dispatcher 回调 goroutine 可能并发写,故用锁串行化(recordWriter 非并发安全)。
type udpPacketWriter struct {
	sync.Mutex
	writer   snellWriter
	response bool // true: 服务端写响应地址;false: 客户端写请求地址
}

func (w *udpPacketWriter) writePacket(payload []byte, dest net.Destination) error {
	if len(payload) > maxPayloadLen {
		return errors.New("snell: udp payload too large ", len(payload))
	}
	buf := make([]byte, 0, 1+1+16+2+len(payload))
	var err error
	if w.response {
		buf, err = appendUDPResponseAddress(buf, dest)
	} else {
		buf = append(buf, udpCommandForward)
		buf, err = appendUDPRequestAddress(buf, dest)
	}
	if err != nil {
		return err
	}
	buf = append(buf, payload...)
	w.Lock()
	defer w.Unlock()
	// 一数据报 = 一个 record(v4/v5 与 v6 统一走 writeDatagram)。
	return w.writer.writeDatagram(buf)
}
